//! From per-token labels to byte spans, mirroring the decoder the models were evaluated
//! with. Offsets are UTF-8 byte offsets into the original text.

use std::collections::BTreeMap;

/// A span the model found.
#[derive(Debug, Clone, PartialEq)]
pub struct Prediction {
    /// The entity label without its B-/I- prefix, such as `PERSON_NAME`.
    pub label: String,
    pub start: usize,
    pub end: usize,
    /// The mean probability of the span's tokens' labels.
    pub score: f32,
}

/// One token's prediction: (start, end) byte offsets, label index and probability.
pub(crate) type Token = (usize, usize, usize, f32);

/// The best prediction per token across overlapping windows: the one from the window in
/// which the token sits furthest from an edge, keyed by the token's start offset.
#[derive(Debug, Default)]
pub(crate) struct Tokens {
    best: BTreeMap<usize, (Token, usize)>,
}

impl Tokens {
    pub(crate) fn offer(&mut self, start: usize, end: usize, tag: usize, prob: f32, margin: usize) {
        if start == end {
            return;
        }
        match self.best.get(&start) {
            Some((_, m)) if *m >= margin => {}
            _ => {
                self.best.insert(start, ((start, end, tag, prob), margin));
            }
        }
    }

    pub(crate) fn in_order(&self) -> Vec<Token> {
        self.best.values().map(|(t, _)| *t).collect()
    }
}

pub(crate) fn softmax_argmax(logits: &[f32]) -> (usize, f32) {
    let max = logits.iter().copied().fold(f32::NEG_INFINITY, f32::max);
    let mut sum = 0.0f32;
    let mut best = (0usize, f32::NEG_INFINITY);
    for (i, &l) in logits.iter().enumerate() {
        sum += (l - max).exp();
        if l > best.1 {
            best = (i, l);
        }
    }
    (
        best.0,
        if sum > 0.0 {
            (best.1 - max).exp() / sum
        } else {
            0.0
        },
    )
}

fn floor_boundary(text: &str, mut i: usize) -> usize {
    i = i.min(text.len());
    while !text.is_char_boundary(i) {
        i -= 1;
    }
    i
}

fn ceil_boundary(text: &str, mut i: usize) -> usize {
    i = i.min(text.len());
    while !text.is_char_boundary(i) {
        i += 1;
    }
    i
}

/// A token's offsets with surrounding whitespace removed, on character boundaries.
pub(crate) fn core(text: &str, start: usize, end: usize) -> (usize, usize) {
    let (start, end) = (floor_boundary(text, start), ceil_boundary(text, end));
    let Some(slice) = text.get(start..end) else {
        return (start, start);
    };
    let lead = slice.len() - slice.trim_start().len();
    let trail = slice.len() - slice.trim_end().len();
    if lead + trail >= slice.len() {
        return (start, start);
    }
    (start + lead, end - trail)
}

const TRAIL: &[char] = &['.', ',', ';', ':', '!', '?', '"', '\''];

/// Drops punctuation a tokenizer merged into a span's edge tokens: sentence punctuation and
/// quotes at the end, and brackets that aren't balanced inside the span.
pub(crate) fn trim(text: &str, mut start: usize, mut end: usize) -> (usize, usize) {
    while end > start {
        let Some(span) = text.get(start..end) else {
            break;
        };
        let opens = span.matches('(').count();
        let closes = span.matches(')').count();
        if let Some(c) = span.chars().next_back() {
            if TRAIL.contains(&c) || (c == ')' && closes > opens) {
                end -= c.len_utf8();
                continue;
            }
        }
        if let Some(c) = span.chars().next() {
            if c == '"' || c == '\'' || (c == '(' && opens > closes) {
                start += c.len_utf8();
                continue;
            }
        }
        break;
    }
    (start, end)
}

/// BIO tags back to spans. An I- tag that doesn't continue a span of the same label starts a
/// new one, so a model that skips the B- tag still yields a span.
pub(crate) fn decode(text: &str, tokens: &[Token], labels: &[String]) -> Vec<Prediction> {
    let mut raw: Vec<(String, usize, usize, Vec<f32>)> = Vec::new();
    let mut cur: Option<(String, usize, usize, Vec<f32>)> = None;
    for &(start, end, tag, prob) in tokens {
        let (s, e) = core(text, start, end);
        if s >= e {
            continue;
        }
        let name = labels.get(tag).map(String::as_str).unwrap_or("O");
        let Some((prefix, label)) = name.split_once('-') else {
            if let Some(c) = cur.take() {
                raw.push(c);
            }
            continue;
        };
        match &mut cur {
            Some(c) if c.0 == label && prefix == "I" => {
                c.2 = e;
                c.3.push(prob);
            }
            _ => {
                if let Some(c) = cur.take() {
                    raw.push(c);
                }
                cur = Some((label.to_string(), s, e, vec![prob]));
            }
        }
    }
    if let Some(c) = cur.take() {
        raw.push(c);
    }
    raw.into_iter()
        .filter_map(|(label, s, e, probs)| {
            let (s, e) = trim(text, s, e);
            let score = probs.iter().sum::<f32>() / probs.len().max(1) as f32;
            (s < e).then_some(Prediction {
                label,
                start: s,
                end: e,
                score,
            })
        })
        .collect()
}

#[cfg(test)]
#[allow(clippy::panic, clippy::indexing_slicing)]
mod tests {
    use super::*;

    fn labels() -> Vec<String> {
        [
            "O",
            "B-PERSON_NAME",
            "I-PERSON_NAME",
            "B-GH_MOBILE_NUMBER",
            "I-GH_MOBILE_NUMBER",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect()
    }

    #[test]
    fn joins_b_and_i_tokens_into_one_span() {
        let text = "Call Ama Mensah now";
        let tokens = [
            (0, 4, 0, 0.9),
            (5, 8, 1, 0.8),
            (9, 15, 2, 0.6),
            (16, 19, 0, 0.9),
        ];
        let got = decode(text, &tokens, &labels());
        assert_eq!(got.len(), 1);
        let p = &got[0];
        assert_eq!((p.label.as_str(), p.start, p.end), ("PERSON_NAME", 5, 15));
        assert!((p.score - 0.7).abs() < 1e-6);
    }

    #[test]
    fn an_orphan_i_tag_starts_a_span() {
        let tokens = [(0, 3, 2, 0.9)];
        let got = decode("Ama", &tokens, &labels());
        assert_eq!(got[0].start, 0);
        assert_eq!(got[0].end, 3);
    }

    #[test]
    fn trims_sentence_punctuation_and_unbalanced_brackets() {
        let text = "+233 24 123 4567).";
        assert_eq!(trim(text, 0, text.len()), (0, 16));
        let quoted = "\"Ama Mensah,\"";
        assert_eq!(trim(quoted, 0, quoted.len()), (1, 11));
        let kept = "+233 (0)24 123 4567";
        assert_eq!(trim(kept, 0, kept.len()), (0, kept.len()));
    }

    #[test]
    fn core_strips_whitespace_and_keeps_char_boundaries() {
        let text = "ɛ Ama";
        assert_eq!(core(text, 2, 6), (3, 6));
        // An offset inside a multi-byte character snaps outward.
        assert_eq!(core(text, 1, 2), (0, 2));
    }

    #[test]
    fn the_most_central_window_wins() {
        let mut t = Tokens::default();
        t.offer(5, 8, 0, 0.9, 0);
        t.offer(5, 8, 1, 0.8, 3);
        t.offer(5, 8, 0, 0.9, 2);
        assert_eq!(t.in_order(), vec![(5, 8, 1, 0.8)]);
    }

    #[test]
    fn softmax_picks_the_largest_logit() {
        let (i, p) = softmax_argmax(&[0.0, 2.0, 0.0]);
        assert_eq!(i, 1);
        assert!((p - 0.786_986).abs() < 1e-5);
    }
}
