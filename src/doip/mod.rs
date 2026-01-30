//! DoIP Protocol Implementation (ISO 13400-2)

pub mod hearder_parser;

// Re-export commonly used types
pub use hearder_parser::{
    DoipCodec, DoipHeader, DoipMessage, GenericNackCode, ParseError, PayloadType, Result,
    DEFAULT_PROTOCOL_VERSION, DEFAULT_PROTOCOL_VERSION_INV, DOIP_HEADER_LENGTH,
    MAX_DOIP_MESSAGE_SIZE,
};
