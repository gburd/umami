#![doc = include_str!("../README.md")]
#![warn(missing_docs)]
#![forbid(unsafe_code)]

pub mod detector;
pub mod pretty;
pub mod profile;
pub mod signature;
pub mod time;
pub mod token;
pub mod tokenizer;

pub use detector::{Anomaly, AnomalyKind, Detector, DetectorConfig};
pub use pretty::Pretty;
pub use profile::{Profile, ProfileStore};
pub use signature::{structure_signature, StructureHash};
pub use token::{Token, TokenType};
pub use tokenizer::{tokenize, Tokenizer};

// The workspace README and the umami(3) page are not part of the crate docs,
// but their examples should still compile and pass.
#[cfg(doctest)]
#[doc = include_str!("../../README.md")]
struct ReadmeDoctests;

#[cfg(doctest)]
#[doc = include_str!("../../man/umami.3.md")]
struct ManPageDoctests;
