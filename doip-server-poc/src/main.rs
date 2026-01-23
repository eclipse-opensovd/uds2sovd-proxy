#![allow(dead_code)]

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream, UdpSocket};
use std::thread;

/* ---------------------------------------------------------
 * DoIP: Routing Activation (TCP)
 * --------------------------------------------------------- */
fn send_routing_activation_response(
    stream: &mut TcpStream,
) -> std::io::Result<()> {
    // DoIP header
    let version: u8 = 0x02;
    let inverse_version: u8 = 0xFD;
    let payload_type: u16 = 0x0006; // Routing Activation Response
    let payload_length: u32 = 9;

    // Minimal positive response payload
    let payload: [u8; 9] = [
        0x10, 0x00, // DoIP entity logical address
        0x00, 0x00, // Reserved
        0x10,       // Routing activation successful
        0x00, 0x00, 0x00, 0x00,
    ];

    let mut message = Vec::with_capacity(8 + payload.len());
    message.push(version);
    message.push(inverse_version);
    message.extend_from_slice(&payload_type.to_be_bytes());
    message.extend_from_slice(&payload_length.to_be_bytes());
    message.extend_from_slice(&payload);

    stream.write_all(&message)?;
    println!("Routing Activation Response sent");

    Ok(())
}

/* ---------------------------------------------------------
 * DoIP: Diagnostic Message Handling
 * --------------------------------------------------------- */
fn parse_diagnostic_message(
    buffer: &[u8],
    bytes_read: usize,
) -> Option<(u16, u16, u8)> {
    // Minimum length:
    // 8 bytes DoIP header + 2 src + 2 tgt + 1 UDS
    if bytes_read < 13 {
        println!("Diagnostic message too short");
        return None;
    }

    let source = u16::from_be_bytes([buffer[8], buffer[9]]);
    let target = u16::from_be_bytes([buffer[10], buffer[11]]);
    let uds_payload = &buffer[12..bytes_read];

    if uds_payload.is_empty() {
        println!("Empty UDS payload");
        return None;
    }

    println!(
        "Diagnostic Message:\n  Source: 0x{:04X}\n  Target: 0x{:04X}\n  UDS: {:02X?}",
        source, target, uds_payload
    );

    Some((source, target, uds_payload[0]))
}

fn send_dummy_diagnostic_response(
    stream: &mut TcpStream,
    source: u16,
    target: u16,
    service_id: u8,
) -> std::io::Result<()> {
    // NRC: Service Not Supported (0x11)
    let uds_response: [u8; 3] = [0x7F, service_id, 0x11];

    let version: u8 = 0x02;
    let inverse_version: u8 = 0xFD;
    let payload_type: u16 = 0x8002; // Diagnostic Response
    let payload_length: u32 = 4 + uds_response.len() as u32;

    let mut message =
        Vec::with_capacity(8 + 4 + uds_response.len());

    message.push(version);
    message.push(inverse_version);
    message.extend_from_slice(&payload_type.to_be_bytes());
    message.extend_from_slice(&payload_length.to_be_bytes());

    // Swap addresses (server → tester)
    message.extend_from_slice(&target.to_be_bytes());
    message.extend_from_slice(&source.to_be_bytes());
    message.extend_from_slice(&uds_response);

    stream.write_all(&message)?;
    println!("Dummy diagnostic response sent");

    Ok(())
}

/* ---------------------------------------------------------
 * DoIP: UDP Vehicle Identification
 * --------------------------------------------------------- */
fn run_udp_vehicle_identification() -> std::io::Result<()> {
    let socket = UdpSocket::bind("0.0.0.0:13400")?;
    println!("UDP discovery listening on port 13400");

    let mut buffer = [0u8; 1024];

    loop {
        let (size, sender) = socket.recv_from(&mut buffer)?;
        if size < 8 {
            continue; // Ignore malformed packets
        }

        println!(
            "Vehicle Identification request from {}",
            sender
        );

        // Static Vehicle Identification Response
        let response: [u8; 18] = [
            0x02, 0xFD,             // Version + inverse
            0x00, 0x04,             // Vehicle ID Response
            0x00, 0x00, 0x00, 0x0A, // Payload length (10 bytes)
            b'D', b'O', b'I', b'P', b'-', b'E', b'C', b'U',
            0x10, 0x00,             // Logical address
        ];

        socket.send_to(&response, sender)?;
        println!("Vehicle Identification Response sent");
    }
}

/* ---------------------------------------------------------
 * Main
 * --------------------------------------------------------- */
fn main() -> std::io::Result<()> {
    // Start UDP discovery in parallel (production merge)
    thread::spawn(|| {
        if let Err(e) = run_udp_vehicle_identification() {
            eprintln!("UDP error: {}", e);
        }
    });

    // TCP DoIP server (existing POC)
    let listener = TcpListener::bind("0.0.0.0:13400")?;
    println!("DoIP TCP Server listening on port 13400");

    let (mut stream, client) = listener.accept()?;
    println!("TCP client connected from {}", client);

    let mut buffer = [0u8; 1024];
    let mut routing_activated = false;

    loop {
        let bytes_read = stream.read(&mut buffer)?;
        if bytes_read == 0 {
            println!("Client disconnected");
            break;
        }

        println!(
            "Received {} bytes: {:02X?}",
            bytes_read,
            &buffer[..bytes_read]
        );

        if bytes_read < 8 {
            continue;
        }

        let payload_type =
            u16::from_be_bytes([buffer[2], buffer[3]]);
        println!("DoIP Payload Type: 0x{:04X}", payload_type);

        match payload_type {
            0x0005 => {
                println!("Routing Activation Request received");
                send_routing_activation_response(&mut stream)?;
                routing_activated = true;
            }
            0x8001 => {
                if !routing_activated {
                    println!(
                        "Diagnostic received before routing activation — ignored"
                    );
                    continue;
                }

                if let Some((src, tgt, sid)) =
                    parse_diagnostic_message(&buffer, bytes_read)
                {
                    send_dummy_diagnostic_response(
                        &mut stream,
                        src,
                        tgt,
                        sid,
                    )?;
                }
            }
            _ => {
                println!("Unhandled DoIP payload type");
            }
        }
    }

    Ok(())
}
