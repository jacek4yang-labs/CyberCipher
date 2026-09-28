//! CyberCipher core: the typed value system, operation model, parameter
//! handling, execution context, error model, and the operation registry.
//!
//! This crate is deliberately free of GUI, I/O, and algorithm code. Every
//! other CyberCipher component (codec, crypto, engine, GUI, CLI) builds on
//! the abstractions defined here.

// OperationError is ~128 bytes (five string fields). Failure paths are cold,
// so boxing the error at every call site is not worth the churn; silence the
// size lint until profiling says otherwise.
#![allow(clippy::result_large_err)]

pub mod context;
pub mod error;
pub mod param;
pub mod registry;
pub mod spec;
pub mod util;
pub mod value;

pub use context::ExecutionContext;
pub use error::{ErrorKind, OpResult, OperationError};
pub use param::{ParamMap, ParamValue};
pub use registry::{Operation, OperationRegistry, SearchHit, SimpleOp};
pub use spec::{
    Category, CostClass, OperationSpec, ParamDefault, ParamKind, ParamOption, ParamSpec,
    Provenance, Security,
};
pub use value::{Value, ValueKind};

/// Convenience prelude for implementing operations.
pub mod prelude {
    pub use crate::context::ExecutionContext;
    pub use crate::error::{ErrorKind, OpResult, OperationError};
    pub use crate::param::{ParamMap, ParamValue};
    pub use crate::registry::{Operation, OperationRegistry, SimpleOp};
    pub use crate::spec::{
        Category, CostClass, OperationSpec, ParamDefault, ParamKind, ParamOption, ParamSpec,
        Provenance, Security,
    };
    pub use crate::util;
    pub use crate::value::{Value, ValueKind};
}
