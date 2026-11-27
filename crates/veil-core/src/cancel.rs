//! Stopping a scan nobody is waiting for any more.
//!
//! A scan can't be interrupted from outside, so a host that gives up on one would otherwise
//! leave it running to the end. With a [`Cancel`] in force the engine looks at it before
//! each detector and the model looks before each batch, and a cancelled scan ends with
//! [`crate::VeilError::Cancelled`] within one such step.
//!
//! ```
//! use veil_core::{Cancel, DetectionContext, Engine, Registry, VeilError};
//!
//! let engine = Engine::new(Registry::new());
//! let cancel = Cancel::new();
//! cancel.cancel();
//! let result = cancel.scope(|| engine.detect("some text", &DetectionContext::default()));
//! assert_eq!(result, Err(VeilError::Cancelled));
//! ```

use std::cell::RefCell;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

thread_local! {
    static IN_FORCE: RefCell<Option<Cancel>> = const { RefCell::new(None) };
}

/// A flag that stops the scans run under it. Clones share the flag, so one can stay with
/// whoever is waiting while another goes to the thread that scans.
#[derive(Debug, Clone, Default)]
pub struct Cancel(Arc<AtomicBool>);

impl Cancel {
    pub fn new() -> Self {
        Self::default()
    }

    /// Stops every scan running under this flag, from any thread.
    pub fn cancel(&self) {
        self.0.store(true, Ordering::Relaxed);
    }

    pub fn is_cancelled(&self) -> bool {
        self.0.load(Ordering::Relaxed)
    }

    /// Runs `scan` on this thread with the flag in force for every engine call it makes.
    pub fn scope<T>(&self, scan: impl FnOnce() -> T) -> T {
        // Puts back the flag that was in force before, even if the scan panics.
        struct Restore(Option<Cancel>);
        impl Drop for Restore {
            fn drop(&mut self) {
                IN_FORCE.with(|c| *c.borrow_mut() = self.0.take());
            }
        }
        let _restore = Restore(IN_FORCE.with(|c| c.borrow_mut().replace(self.clone())));
        scan()
    }
}

/// Whether the scan running on this thread has been cancelled. A detector that takes long
/// over one text can ask this between its own steps.
pub fn cancelled() -> bool {
    IN_FORCE.with(|c| c.borrow().as_ref().is_some_and(Cancel::is_cancelled))
}
