//! DoIP Header Parser

use bytes::{Buf, BufMut, Bytes, BytesMut};
use std::io;
use tokio_util::codec::{Decoder, Encoder};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum GenericNackCode {
    IncorrectPatternFormat = 0x00,
    UnknownPayloadType = 0x01,
    MessageTooLarge = 0x02,
    OutOfMemory = 0x03,
    InvalidPayloadLength = 0x04,
}

#[derive(Debug)]
pub enum ParseError {
    InvalidHeader(String),
    Io(io::Error),
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidHeader(msg) => write!(f, "Invalid header: {}", msg),
            Self::Io(e) => write!(f, "IO error: {}", e),
        }
    }
}

impl std::error::Error for ParseError {}

impl From<io::Error> for ParseError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

pub type Result<T> = std::result::Result<T, ParseError>;

pub const DEFAULT_PROTOCOL_VERSION: u8 = 0x02;
pub const DEFAULT_PROTOCOL_VERSION_INV: u8 = 0xFD;
pub const DOIP_HEADER_LENGTH: usize = 8;
pub const MAX_DOIP_MESSAGE_SIZE: u32 = 0x0FFF_FFFF;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum PayloadType {
    GenericNack = 0x0000,
    VehicleIdentificationRequest = 0x0001,
    VehicleIdentificationRequestWithEid = 0x0002,
    VehicleIdentificationRequestWithVin = 0x0003,
    VehicleIdentificationResponse = 0x0004,
    RoutingActivationRequest = 0x0005,
    RoutingActivationResponse = 0x0006,
    AliveCheckRequest = 0x0007,
    AliveCheckResponse = 0x0008,
    DoipEntityStatusRequest = 0x4001,
    DoipEntityStatusResponse = 0x4002,
    DiagnosticPowerModeRequest = 0x4003,
    DiagnosticPowerModeResponse = 0x4004,
    DiagnosticMessage = 0x8001,
    DiagnosticMessagePositiveAck = 0x8002,
    DiagnosticMessageNegativeAck = 0x8003,
}

impl PayloadType {
    pub fn from_u16(value: u16) -> Option<Self> {
        match value {
            0x0000 => Some(Self::GenericNack),
            0x0001 => Some(Self::VehicleIdentificationRequest),
            0x0002 => Some(Self::VehicleIdentificationRequestWithEid),
            0x0003 => Some(Self::VehicleIdentificationRequestWithVin),
            0x0004 => Some(Self::VehicleIdentificationResponse),
            0x0005 => Some(Self::RoutingActivationRequest),
            0x0006 => Some(Self::RoutingActivationResponse),
            0x0007 => Some(Self::AliveCheckRequest),
            0x0008 => Some(Self::AliveCheckResponse),
            0x4001 => Some(Self::DoipEntityStatusRequest),
            0x4002 => Some(Self::DoipEntityStatusResponse),
            0x4003 => Some(Self::DiagnosticPowerModeRequest),
            0x4004 => Some(Self::DiagnosticPowerModeResponse),
            0x8001 => Some(Self::DiagnosticMessage),
            0x8002 => Some(Self::DiagnosticMessagePositiveAck),
            0x8003 => Some(Self::DiagnosticMessageNegativeAck),
            _ => None,
        }
    }

    pub const fn min_payload_length(self) -> usize {
        match self {
            Self::GenericNack => 1,
            Self::VehicleIdentificationRequest => 0,
            Self::VehicleIdentificationRequestWithEid => 6,
            Self::VehicleIdentificationRequestWithVin => 17,
            Self::VehicleIdentificationResponse => 32,
            Self::RoutingActivationRequest => 7,
            Self::RoutingActivationResponse => 9,
            Self::AliveCheckRequest => 0,
            Self::AliveCheckResponse => 2,
            Self::DoipEntityStatusRequest => 0,
            Self::DoipEntityStatusResponse => 3,
            Self::DiagnosticPowerModeRequest => 0,
            Self::DiagnosticPowerModeResponse => 1,
            Self::DiagnosticMessage => 5,
            Self::DiagnosticMessagePositiveAck => 5,
            Self::DiagnosticMessageNegativeAck => 5,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DoipHeader {
    pub version: u8,
    pub inverse_version: u8,
    pub payload_type: u16,
    pub payload_length: u32,
}

impl DoipHeader {
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < DOIP_HEADER_LENGTH {
            return Err(ParseError::InvalidHeader(format!(
                "header too short: expected {}, got {}",
                DOIP_HEADER_LENGTH,
                data.len()
            )));
        }
        Ok(Self {
            version: data[0],
            inverse_version: data[1],
            payload_type: u16::from_be_bytes([data[2], data[3]]),
            payload_length: u32::from_be_bytes([data[4], data[5], data[6], data[7]]),
        })
    }

    pub fn parse_from_buf(buf: &mut Bytes) -> Result<Self> {
        if buf.len() < DOIP_HEADER_LENGTH {
            return Err(ParseError::InvalidHeader(format!(
                "header too short: expected {}, got {}",
                DOIP_HEADER_LENGTH,
                buf.len()
            )));
        }
        Ok(Self {
            version: buf.get_u8(),
            inverse_version: buf.get_u8(),
            payload_type: buf.get_u16(),
            payload_length: buf.get_u32(),
        })
    }

    pub fn validate(&self) -> Option<GenericNackCode> {
        if self.version != DEFAULT_PROTOCOL_VERSION {
            return Some(GenericNackCode::IncorrectPatternFormat);
        }
        if self.inverse_version != DEFAULT_PROTOCOL_VERSION_INV {
            return Some(GenericNackCode::IncorrectPatternFormat);
        }
        if self.version ^ self.inverse_version != 0xFF {
            return Some(GenericNackCode::IncorrectPatternFormat);
        }

        let payload_type = match PayloadType::from_u16(self.payload_type) {
            Some(pt) => pt,
            None => return Some(GenericNackCode::UnknownPayloadType),
        };

        if self.payload_length > MAX_DOIP_MESSAGE_SIZE {
            return Some(GenericNackCode::MessageTooLarge);
        }
        if (self.payload_length as usize) < payload_type.min_payload_length() {
            return Some(GenericNackCode::InvalidPayloadLength);
        }
        None
    }

    pub fn is_valid(&self) -> bool {
        self.validate().is_none()
    }

    pub const fn total_length(&self) -> usize {
        DOIP_HEADER_LENGTH + self.payload_length as usize
    }

    pub fn to_bytes(&self) -> Bytes {
        let mut buf = BytesMut::with_capacity(DOIP_HEADER_LENGTH);
        buf.put_u8(self.version);
        buf.put_u8(self.inverse_version);
        buf.put_u16(self.payload_type);
        buf.put_u32(self.payload_length);
        buf.freeze()
    }

    pub fn write_to(&self, buf: &mut BytesMut) {
        buf.put_u8(self.version);
        buf.put_u8(self.inverse_version);
        buf.put_u16(self.payload_type);
        buf.put_u32(self.payload_length);
    }
}

impl Default for DoipHeader {
    fn default() -> Self {
        Self {
            version: DEFAULT_PROTOCOL_VERSION,
            inverse_version: DEFAULT_PROTOCOL_VERSION_INV,
            payload_type: 0,
            payload_length: 0,
        }
    }
}

impl std::fmt::Display for DoipHeader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let payload_name = PayloadType::from_u16(self.payload_type)
            .map(|pt| format!("{:?}", pt))
            .unwrap_or_else(|| format!("Unknown(0x{:04X})", self.payload_type));
        write!(
            f,
            "DoipHeader {{ version: 0x{:02X}, type: {}, length: {} }}",
            self.version, payload_name, self.payload_length
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DoipMessage {
    pub header: DoipHeader,
    pub payload: Bytes,
}

impl DoipMessage {
    pub fn new(payload_type: PayloadType, payload: Bytes) -> Self {
        Self {
            header: DoipHeader {
                version: DEFAULT_PROTOCOL_VERSION,
                inverse_version: DEFAULT_PROTOCOL_VERSION_INV,
                payload_type: payload_type as u16,
                payload_length: payload.len() as u32,
            },
            payload,
        }
    }

    pub fn with_raw_type(payload_type: u16, payload: Bytes) -> Self {
        Self {
            header: DoipHeader {
                version: DEFAULT_PROTOCOL_VERSION,
                inverse_version: DEFAULT_PROTOCOL_VERSION_INV,
                payload_type,
                payload_length: payload.len() as u32,
            },
            payload,
        }
    }

    pub fn payload_type(&self) -> Option<PayloadType> {
        PayloadType::from_u16(self.header.payload_type)
    }

    pub fn total_length(&self) -> usize {
        DOIP_HEADER_LENGTH + self.payload.len()
    }

    pub fn to_bytes(&self) -> Bytes {
        let mut buf = BytesMut::with_capacity(self.total_length());
        self.header.write_to(&mut buf);
        buf.extend_from_slice(&self.payload);
        buf.freeze()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DecodeState {
    Header,
    Payload(DoipHeader),
}

#[derive(Debug)]
pub struct DoipCodec {
    state: DecodeState,
    max_payload_size: u32,
}

impl DoipCodec {
    pub fn new() -> Self {
        Self {
            state: DecodeState::Header,
            max_payload_size: MAX_DOIP_MESSAGE_SIZE,
        }
    }

    pub fn with_max_payload_size(max_size: u32) -> Self {
        Self {
            state: DecodeState::Header,
            max_payload_size: max_size,
        }
    }
}

impl Default for DoipCodec {
    fn default() -> Self {
        Self::new()
    }
}

impl Decoder for DoipCodec {
    type Item = DoipMessage;
    type Error = io::Error;

    fn decode(
        &mut self,
        src: &mut BytesMut,
    ) -> std::result::Result<Option<Self::Item>, Self::Error> {
        loop {
            match self.state {
                DecodeState::Header => {
                    if src.len() < DOIP_HEADER_LENGTH {
                        src.reserve(DOIP_HEADER_LENGTH);
                        return Ok(None);
                    }

                    let header = DoipHeader::parse(&src[..DOIP_HEADER_LENGTH])
                        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

                    if let Some(nack_code) = header.validate() {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!("validation failed: {:?}", nack_code),
                        ));
                    }

                    if header.payload_length > self.max_payload_size {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!(
                                "payload too large: {} > {}",
                                header.payload_length, self.max_payload_size
                            ),
                        ));
                    }

                    src.reserve(header.total_length());
                    self.state = DecodeState::Payload(header);
                }

                DecodeState::Payload(header) => {
                    if src.len() < header.total_length() {
                        return Ok(None);
                    }

                    let _ = src.split_to(DOIP_HEADER_LENGTH);
                    let payload = src.split_to(header.payload_length as usize).freeze();

                    self.state = DecodeState::Header;
                    return Ok(Some(DoipMessage { header, payload }));
                }
            }
        }
    }
}

impl Encoder<DoipMessage> for DoipCodec {
    type Error = io::Error;

    fn encode(
        &mut self,
        item: DoipMessage,
        dst: &mut BytesMut,
    ) -> std::result::Result<(), Self::Error> {
        dst.reserve(item.total_length());
        item.header.write_to(dst);
        dst.extend_from_slice(&item.payload);
        Ok(())
    }
}
