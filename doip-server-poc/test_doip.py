#!/usr/bin/env python3
"""DoIP Server Test Script"""

import socket
import time

HOST = '127.0.0.1'
PORT = 13400


def test_udp_vehicle_discovery():
    """Test UDP Vehicle Identification Request"""
    print("\n=== UDP Vehicle Discovery Test ===")
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(3)
    
    # DoIP Vehicle Identification Request (payload type 0x0001)
    request = bytes([
        0x02, 0xFD,             # Protocol version + inverse
        0x00, 0x01,             # Payload type: Vehicle ID Request
        0x00, 0x00, 0x00, 0x00  # Payload length: 0
    ])
    
    print(f"Sending: {request.hex()}")
    sock.sendto(request, (HOST, PORT))
    
    try:
        response, addr = sock.recvfrom(1024)
        print(f"Response from {addr}: {response.hex()}")
        print(f"  Vehicle ID: {response[8:16].decode('ascii', errors='ignore')}")
    except socket.timeout:
        print("No response (timeout)")
    
    sock.close()


def test_tcp_routing_activation():
    """Test TCP Routing Activation"""
    print("\n=== TCP Routing Activation Test ===")
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5)
    sock.connect((HOST, PORT))
    print(f"Connected to {HOST}:{PORT}")
    
    # DoIP Routing Activation Request (payload type 0x0005)
    request = bytes([
        0x02, 0xFD,             # Protocol version + inverse
        0x00, 0x05,             # Payload type: Routing Activation Request
        0x00, 0x00, 0x00, 0x07, # Payload length: 7
        0x0E, 0x00,             # Source address (tester)
        0x00,                   # Activation type
        0x00, 0x00, 0x00, 0x00  # Reserved
    ])
    
    print(f"Sending Routing Activation: {request.hex()}")
    sock.send(request)
    
    response = sock.recv(1024)
    print(f"Response: {response.hex()}")
    
    if len(response) >= 13:
        payload_type = int.from_bytes(response[2:4], 'big')
        if payload_type == 0x0006:
            print("  ✓ Routing Activation Response received")
            activation_code = response[12]
            print(f"  Activation code: 0x{activation_code:02X}")
    
    return sock


def test_tcp_diagnostic_message(sock):
    """Test TCP Diagnostic Message (requires active routing)"""
    print("\n=== TCP Diagnostic Message Test ===")
    
    # UDS: Read Data By Identifier (0x22) - Read ECU Serial Number (0xF18C)
    uds_payload = bytes([0x22, 0xF1, 0x8C])
    
    payload_length = 4 + len(uds_payload)  # src(2) + tgt(2) + uds
    
    # DoIP Diagnostic Message (payload type 0x8001)
    request = bytes([
        0x02, 0xFD,             # Protocol version + inverse
        0x80, 0x01,             # Payload type: Diagnostic Message
        0x00, 0x00, 0x00, payload_length,
        0x0E, 0x00,             # Source address (tester)
        0x10, 0x00,             # Target address (ECU)
    ]) + uds_payload
    
    print(f"Sending Diagnostic (UDS 0x22): {request.hex()}")
    sock.send(request)
    
    response = sock.recv(1024)
    print(f"Response: {response.hex()}")
    
    if len(response) >= 12:
        payload_type = int.from_bytes(response[2:4], 'big')
        if payload_type == 0x8002:
            print("  ✓ Diagnostic Response received")
            uds_response = response[12:]
            print(f"  UDS Response: {uds_response.hex()}")
            if uds_response[0] == 0x7F:
                print(f"  Negative Response: Service 0x{uds_response[1]:02X}, NRC 0x{uds_response[2]:02X}")


def main():
    print("DoIP Server Test Script")
    print("=" * 40)
    print(f"Target: {HOST}:{PORT}")
    
    # Test 1: UDP Discovery
    try:
        test_udp_vehicle_discovery()
    except Exception as e:
        print(f"UDP test failed: {e}")
    
    time.sleep(0.5)
    
    # Test 2: TCP Routing + Diagnostic
    try:
        sock = test_tcp_routing_activation()
        time.sleep(0.5)
        test_tcp_diagnostic_message(sock)
        sock.close()
    except Exception as e:
        print(f"TCP test failed: {e}")
    
    print("\n=== Tests Complete ===")


if __name__ == "__main__":
    main()
