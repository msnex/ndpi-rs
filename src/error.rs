use std::{error::Error, fmt::Display};

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum NdpiError {
    InitNdpiGlobalCtx,
    InitNdpiDetectionModule,
    FinalizeNdpiDetectionModule,
    InitNdpiFlow,
}

impl Display for NdpiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            Self::InitNdpiGlobalCtx => write!(f, "initialize ndpi global context failed"),
            Self::InitNdpiDetectionModule => write!(f, "initialize ndpi detection module failed"),
            Self::FinalizeNdpiDetectionModule => {
                write!(f, "finalize initialization detection module failed")
            }
            Self::InitNdpiFlow => write!(f, "initialize ndpi flow failed"),
        }
    }
}

impl Error for NdpiError {}
