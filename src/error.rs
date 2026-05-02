use thiserror::Error;

#[derive(Debug, Error)]
pub enum NdpiError {
    #[error("Failed to init ndpi global context")]
    InitNdpiGlobalCtx,
    #[error("Failed to set config, param: {0}, value: {1}, error: {2}")]
    SetDetectionConfig(String, String, i32),
    #[error("Failed to init ndpi detection module")]
    InitNdpiDetectionModule,
    #[error("Failed to finalize initialization detection module")]
    FinalizeNdpiDetectionModule,
    #[error("Failed to init ndpi flow")]
    InitNdpiFlow,
}
