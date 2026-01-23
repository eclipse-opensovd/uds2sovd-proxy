# DoIP Server POC

A minimal Diagnostics over IP (DoIP) server implementation in Rust for proof-of-concept and testing purposes.

## Overview

This project implements a DoIP server according to ISO 13400-2, supporting:
- **UDP Vehicle Identification** (Discovery)
- **TCP Routing Activation** (Session establishment)
- **TCP Diagnostic Messages** (UDS over DoIP)

## Architecture

```
┌──────────────┐     UDP/TCP      ┌──────────────────┐
│  UDS Tester  │ ───────────────► │  DoIP Server     │
│  (Client)    │     Port 13400   │  (This Project)  │
│              │ ◄─────────────── │                  │
└──────────────┘                  └──────────────────┘
```

## Features

| Feature | Payload Type | Status |
|---------|--------------|--------|
| Vehicle Identification Request | 0x0001 | ✅ |
| Vehicle Identification Response | 0x0004 | ✅ |
| Routing Activation Request | 0x0005 | ✅ |
| Routing Activation Response | 0x0006 | ✅ |
| Diagnostic Message | 0x8001 | ✅ |
| Diagnostic Message Response | 0x8002 | ✅ |

## Prerequisites

- Rust 1.70+ ([Install Rust](https://rustup.rs/))
- Python 3.x (for testing)

## Build & Run

```bash
# Build
cargo build

# Run
cargo run
```

The server listens on:
- **UDP 13400** - Vehicle discovery
- **TCP 13400** - Diagnostic communication

## Testing

### Using the Python Test Script

```bash
python3 test_doip.py
```

### Manual Testing with netcat

**UDP Discovery:**
```bash
echo -ne '\x02\xFD\x00\x01\x00\x00\x00\x00' | nc -u 127.0.0.1 13400
```

**TCP Routing Activation:**
```bash
echo -ne '\x02\xFD\x00\x05\x00\x00\x00\x07\x0E\x00\x00\x00\x00\x00\x00' | nc 127.0.0.1 13400
```

## Protocol Flow

### 1. Vehicle Discovery (UDP)
```
Tester → Server: Vehicle Identification Request (0x0001)
Server → Tester: Vehicle Identification Response (0x0004)
```

### 2. Session Establishment (TCP)
```
Tester → Server: TCP Connect (port 13400)
Tester → Server: Routing Activation Request (0x0005)
Server → Tester: Routing Activation Response (0x0006)
```

### 3. Diagnostic Communication (TCP)
```
Tester → Server: Diagnostic Message (0x8001) + UDS payload
Server → Tester: Diagnostic Response (0x8002) + UDS response
```

## DoIP Message Structure

| Offset | Size | Field |
|--------|------|-------|
| 0 | 1 | Protocol Version (0x02) |
| 1 | 1 | Inverse Version (0xFD) |
| 2-3 | 2 | Payload Type (big-endian) |
| 4-7 | 4 | Payload Length (big-endian) |
| 8+ | N | Payload Data |

## Configuration

| Parameter | Value | Description |
|-----------|-------|-------------|
| Port | 13400 | DoIP standard port |
| Logical Address | 0x1000 | ECU address |
| Vehicle ID | "DOIP-ECU" | Identification string |

## Project Structure

```
DoIPServer-POC/
├── Cargo.toml          # Rust dependencies
├── README.md           # This file
├── src/
│   └── main.rs         # Server implementation
├── test_doip.py        # Python test script
└── flowchartw/
    └── flowchart.md    # Protocol flowchart
```

## Limitations (POC Scope)

- Single TCP client support
- Dummy UDS responses (NRC 0x11 - Service Not Supported)
- No TLS/security
- Hardcoded configuration
## License

MIT License
