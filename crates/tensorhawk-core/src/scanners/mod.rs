//! Scanner plugin interface and the built-in registry.
//!
//! Every detection module implements [`Scanner`]. Scanners are pure functions
//! of an [`Artifact`]: they read structure and return findings, never mutating
//! shared state. This makes them trivially parallelizable and independently
//! testable, and is the seam where out-of-tree/community scanners plug in.

use crate::artifact::Artifact;
use crate::finding::Finding;

pub mod entropy;
pub mod metadata;
pub mod pickle;
pub mod pii;
pub mod secrets;

pub trait Scanner: Send + Sync {
    /// Stable short identifier, e.g. `pickle`.
    fn id(&self) -> &'static str;
    /// One-line human description.
    fn description(&self) -> &'static str;
    fn scan(&self, artifact: &Artifact) -> Vec<Finding>;
}

/// The default set of built-in scanners, in execution order.
pub fn builtin_scanners() -> Vec<Box<dyn Scanner>> {
    vec![
        Box::new(pickle::PickleScanner),
        Box::new(secrets::SecretScanner::new()),
        Box::new(pii::PiiScanner::new()),
        Box::new(metadata::MetadataScanner::new()),
        Box::new(entropy::EntropyScanner),
    ]
}
