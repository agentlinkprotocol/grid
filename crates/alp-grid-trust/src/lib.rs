//! Trust: the four pillars made concrete.
//!
//! * [`challenge`]: who may challenge whom at a given drand round, and signed challenges.
//! * [`seniority`]: service seniority, the time-earned weight of a node identity.
//! * [`reputation`]: local, evidence-based scores with EigenTrust-style weighting of others' opinions.
//! * [`quota`]: publication quota derived from proven contribution.
//! * [`diversity`]: guardian selection with the per-operator / per-prefix caps.
//! * [`ledger`]: the append-only Merkle ledger of public facts.

pub mod challenge;
pub mod diversity;
pub mod ledger;
pub mod quota;
pub mod reputation;
pub mod seniority;

pub use challenge::*;
pub use diversity::*;
pub use ledger::*;
pub use quota::*;
pub use reputation::*;
pub use seniority::*;
