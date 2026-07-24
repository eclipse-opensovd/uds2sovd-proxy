// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 The Contributors to Eclipse OpenSOVD (see CONTRIBUTORS)
//
// See the NOTICE file(s) distributed with this work for additional
// information regarding copyright ownership.
//
// This program and the accompanying materials are made available under the
// terms of the Apache License Version 2.0 which is available at
// https://www.apache.org/licenses/LICENSE-2.0

//! DoIP tester tool - simulates the external UDS tester.
//!
//! The server (`uds2sovd-proxy`) must be running in order for this tester tool
//! to connect and verify the functionality.
//!
//! # Usage
//! ```sh
//! # Terminal 1: start the server
//! cargo run --bin uds2sovd-proxy
//!
//! # Terminal 2: run the tester
//! cargo run --bin doip-tester
//! ```
//!

use std::io::{Read, Write};
use std::net::{TcpStream, UdpSocket};
use std::time::Duration;

const PROTOCOL_VERSION: u8 = 0xFD;
const INVERSE_VERSION: u8 = 0x02;
const HEADER_LEN: usize = 8;
const SERVER_TCP: &str = "127.0.0.1:13400";
const SERVER_UDP: &str = "127.0.0.1:13400";
const TIMEOUT: Duration = Duration::from_secs(2);

// Helpers

/// Constructs an 8-byte DoIP generic header followed by the payload.
fn build_frame(payload_type: u16, payload: &[u8]) -> Vec<u8> {
    let len = payload.len() as u32;
    let mut frame = Vec::with_capacity(HEADER_LEN + payload.len());
    frame.push(PROTOCOL_VERSION);
    frame.push(INVERSE_VERSION);
    frame.extend_from_slice(&payload_type.to_be_bytes());
    frame.extend_from_slice(&len.to_be_bytes());
    frame.extend_from_slice(payload);
    frame
}

/// Sends a UDP frame and returns the parsed (payload_type, payload) from the response.
fn udp_roundtrip(payload_type: u16, payload: &[u8]) -> Result<(u16, Vec<u8>), String> {
    let socket = UdpSocket::bind("0.0.0.0:0").map_err(|e| format!("bind: {e}"))?;
    socket
        .set_read_timeout(Some(TIMEOUT))
        .map_err(|e| format!("timeout: {e}"))?;
    socket
        .send_to(&build_frame(payload_type, payload), SERVER_UDP)
        .map_err(|e| format!("send: {e}"))?;
    let mut buf = [0u8; 256];
    let n = socket.recv(&mut buf).map_err(|e| format!("recv: {e}"))?;
    parse_response(&buf[..n])
}

/// Sends raw bytes over UDP and returns the parsed response.
fn udp_raw_roundtrip(raw: &[u8]) -> Result<(u16, Vec<u8>), String> {
    let socket = UdpSocket::bind("0.0.0.0:0").map_err(|e| format!("bind: {e}"))?;
    socket
        .set_read_timeout(Some(TIMEOUT))
        .map_err(|e| format!("timeout: {e}"))?;
    socket
        .send_to(raw, SERVER_UDP)
        .map_err(|e| format!("send: {e}"))?;
    let mut buf = [0u8; 256];
    let n = socket.recv(&mut buf).map_err(|e| format!("recv: {e}"))?;
    parse_response(&buf[..n])
}

/// Sends a TCP frame on an existing stream and returns the parsed response.
fn tcp_roundtrip(
    stream: &mut TcpStream,
    payload_type: u16,
    payload: &[u8],
) -> Result<(u16, Vec<u8>), String> {
    stream
        .write_all(&build_frame(payload_type, payload))
        .map_err(|e| format!("write: {e}"))?;
    let mut buf = [0u8; 256];
    let n = stream.read(&mut buf).map_err(|e| format!("read: {e}"))?;
    parse_response(&buf[..n])
}

/// Sends raw bytes on a fresh TCP connection and returns the parsed response.
fn tcp_raw_roundtrip(raw: &[u8]) -> Result<(u16, Vec<u8>), String> {
    let mut stream = TcpStream::connect(SERVER_TCP).map_err(|e| format!("connect: {e}"))?;
    stream
        .set_read_timeout(Some(TIMEOUT))
        .map_err(|e| format!("timeout: {e}"))?;
    stream.write_all(raw).map_err(|e| format!("write: {e}"))?;
    let mut buf = [0u8; 256];
    let n = stream.read(&mut buf).map_err(|e| format!("read: {e}"))?;
    parse_response(&buf[..n])
}

/// Parses a DoIP response buffer into (payload_type, payload_bytes).
fn parse_response(data: &[u8]) -> Result<(u16, Vec<u8>), String> {
    if data.len() < HEADER_LEN {
        return Err("response too short for header".into());
    }
    let payload_type = u16::from_be_bytes([data[2], data[3]]);
    let payload_len = u32::from_be_bytes([data[4], data[5], data[6], data[7]]) as usize;
    if data.len() < HEADER_LEN + payload_len {
        return Err(format!(
            "response truncated: have {}, need {}",
            data.len(),
            HEADER_LEN + payload_len
        ));
    }
    Ok((
        payload_type,
        data[HEADER_LEN..HEADER_LEN + payload_len].to_vec(),
    ))
}

/// Asserts the response payload type matches the expected value.
fn expect_type(actual: u16, expected: u16) -> Result<(), String> {
    if actual != expected {
        Err(format!(
            "expected type 0x{expected:04X}, got 0x{actual:04X}"
        ))
    } else {
        Ok(())
    }
}

/// Asserts the response is a NACK (0x0000) with the expected code byte.
fn expect_nack(response_type: u16, payload: &[u8], expected_code: u8) -> Result<(), String> {
    expect_type(response_type, 0x0000)?;
    let actual = payload.first().copied().unwrap_or(0xFF);
    if actual != expected_code {
        Err(format!(
            "expected NACK code 0x{expected_code:02X}, got 0x{actual:02X}"
        ))
    } else {
        Ok(())
    }
}

// UDP Tests                     --

/// 0x0001 VehicleIdentificationRequest → 0x0004 VehicleAnnouncement (32 bytes).
fn test_udp_vehicle_id() -> Result<(), String> {
    let (ptype, payload) = udp_roundtrip(0x0001, &[])?;
    expect_type(ptype, 0x0004)?;
    if payload.len() < 32 {
        return Err(format!("payload {}/32 bytes", payload.len()));
    }
    let addr = u16::from_be_bytes([payload[17], payload[18]]);
    if addr != 0x0001 {
        return Err(format!("logical address 0x{addr:04X}, expected 0x0001"));
    }
    Ok(())
}

/// 0x0002 VehicleIdentificationRequestWithEid → 0x0004 VehicleAnnouncement.
fn test_udp_vehicle_id_by_eid() -> Result<(), String> {
    let (ptype, payload) = udp_roundtrip(0x0002, &[0x00; 6])?;
    expect_type(ptype, 0x0004)?;
    if payload.len() < 32 {
        return Err(format!("payload {}/32 bytes", payload.len()));
    }
    Ok(())
}

/// 0x0003 VehicleIdentificationRequestWithVin → 0x0004 VehicleAnnouncement.
fn test_udp_vehicle_id_by_vin() -> Result<(), String> {
    let (ptype, payload) = udp_roundtrip(0x0003, b"00000000000000000")?;
    expect_type(ptype, 0x0004)?;
    if payload.len() < 32 {
        return Err(format!("payload {}/32 bytes", payload.len()));
    }
    Ok(())
}

/// 0x4001 EntityStatusRequest → 0x4002 EntityStatusResponse (7 bytes).
fn test_udp_entity_status() -> Result<(), String> {
    let (ptype, payload) = udp_roundtrip(0x4001, &[])?;
    expect_type(ptype, 0x4002)?;
    if payload.len() < 7 {
        return Err(format!("payload {}/7 bytes", payload.len()));
    }
    Ok(())
}

/// Invalid protocol version (0xFF) over UDP → NACK 0x00 (incorrect pattern).
fn test_udp_invalid_version() -> Result<(), String> {
    let mut frame = build_frame(0x0001, &[]);
    frame[0] = 0xFF;
    let (ptype, payload) = udp_raw_roundtrip(&frame)?;
    expect_nack(ptype, &payload, 0x00)
}

// TCP Tests                     --

/// 0x0005 RoutingActivationRequest → 0x0006 RoutingActivationResponse (code 0x10).
/// Returns the stream for reuse by subsequent TCP tests.
fn test_tcp_routing_activation() -> Result<TcpStream, String> {
    let mut stream = TcpStream::connect(SERVER_TCP).map_err(|e| format!("connect: {e}"))?;
    stream
        .set_read_timeout(Some(TIMEOUT))
        .map_err(|e| format!("timeout: {e}"))?;
    let (ptype, resp) = tcp_roundtrip(
        &mut stream,
        0x0005,
        &[
            0x0E, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ],
    )?;
    expect_type(ptype, 0x0006)?;
    if resp[0] != 0x0E || resp[1] != 0x00 {
        return Err(format!(
            "echoed source 0x{:02X}{:02X}, expected 0x0E00",
            resp[0], resp[1]
        ));
    }
    if resp[4] != 0x10 {
        return Err(format!("activation code 0x{:02X}, expected 0x10", resp[4]));
    }
    Ok(stream)
}

/// 0x0007 AliveCheckRequest → 0x0008 AliveCheckResponse (2-byte logical address).
fn test_tcp_alive_check(stream: &mut TcpStream) -> Result<(), String> {
    let (ptype, payload) = tcp_roundtrip(stream, 0x0007, &[])?;
    expect_type(ptype, 0x0008)?;
    let addr = u16::from_be_bytes([payload[0], payload[1]]);
    if addr != 0x0001 {
        return Err(format!("logical address 0x{addr:04X}, expected 0x0001"));
    }
    Ok(())
}

/// 0x8001 DiagnosticMessage (TesterPresent 0x3E) → 0x8002 PositiveAck.
fn test_tcp_diagnostic_tester_present(stream: &mut TcpStream) -> Result<(), String> {
    let (ptype, _) = tcp_roundtrip(stream, 0x8001, &[0x0E, 0x00, 0x00, 0x01, 0x3E, 0x00])?;
    expect_type(ptype, 0x8002)
}

/// Invalid protocol version (0xFF) over TCP → NACK 0x00 (incorrect pattern).
fn test_tcp_invalid_version() -> Result<(), String> {
    let mut frame = build_frame(
        0x0005,
        &[
            0x0E, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ],
    );
    frame[0] = 0xFF;
    let (ptype, payload) = tcp_raw_roundtrip(&frame)?;
    expect_nack(ptype, &payload, 0x00)
}

/// Unknown payload type (0xBEEF) over TCP → NACK 0x01 (unknown payload type).
fn test_tcp_unknown_payload_type() -> Result<(), String> {
    let (ptype, payload) = tcp_raw_roundtrip(&build_frame(0xBEEF, &[]))?;
    expect_nack(ptype, &payload, 0x01)
}

// Main                       -

fn main() {
    println!("=== DoIP Tester ===\n");
    let mut passed = 0u32;
    let mut failed = 0u32;

    // UDP tests
    for (name, test_fn) in [
        (
            "udp_vehicle_id",
            test_udp_vehicle_id as fn() -> Result<(), String>,
        ),
        ("udp_vehicle_id_by_eid", test_udp_vehicle_id_by_eid),
        ("udp_vehicle_id_by_vin", test_udp_vehicle_id_by_vin),
        ("udp_entity_status", test_udp_entity_status),
        ("udp_invalid_version", test_udp_invalid_version),
    ] {
        match test_fn() {
            Ok(()) => {
                println!("[PASS] {name}");
                passed += 1;
            }
            Err(e) => {
                println!("[FAIL] {name} - {e}");
                failed += 1;
            }
        }
    }

    // TCP happy-path tests (shared connection: routing → alive → diagnostic)
    let stream = match test_tcp_routing_activation() {
        Ok(s) => {
            println!("[PASS] tcp_routing_activation");
            passed += 1;
            Some(s)
        }
        Err(e) => {
            println!("[FAIL] tcp_routing_activation - {e}");
            failed += 1;
            None
        }
    };
    if let Some(mut s) = stream {
        for (name, test_fn) in [
            (
                "tcp_alive_check",
                test_tcp_alive_check as fn(&mut TcpStream) -> Result<(), String>,
            ),
            (
                "tcp_diagnostic_tester_present",
                test_tcp_diagnostic_tester_present,
            ),
        ] {
            match test_fn(&mut s) {
                Ok(()) => {
                    println!("[PASS] {name}");
                    passed += 1;
                }
                Err(e) => {
                    println!("[FAIL] {name} - {e}");
                    failed += 1;
                }
            }
        }
    } else {
        println!("[SKIP] tcp_alive_check - no TCP connection");
        println!("[SKIP] tcp_diagnostic_tester_present - no TCP connection");
    }

    // TCP error tests (separate connections)
    for (name, test_fn) in [
        (
            "tcp_invalid_version",
            test_tcp_invalid_version as fn() -> Result<(), String>,
        ),
        ("tcp_unknown_payload_type", test_tcp_unknown_payload_type),
    ] {
        match test_fn() {
            Ok(()) => {
                println!("[PASS] {name}");
                passed += 1;
            }
            Err(e) => {
                println!("[FAIL] {name} - {e}");
                failed += 1;
            }
        }
    }

    let total = passed + failed;
    println!("\n=== {passed}/{total} passed ===");
    std::process::exit(if failed > 0 { 1 } else { 0 });
}
