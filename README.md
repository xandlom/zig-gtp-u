# zig-gtp-u

High-performance GPRS Tunneling Protocol User Plane (GTP-U) implementation for 5G networks written in Zig.

## Features

### Core GTP-U Protocol (3GPP TS 29.281)

- ✅ **Complete Protocol Implementation**
  - G-PDU (user data tunneling)
  - Echo Request/Response (path management)
  - Error Indication
  - End Marker
  - Supported Extension Headers Notification

- ✅ **5G Network Interfaces**
  - N3 interface (gNB ↔ UPF)
  - N9 interface (UPF ↔ UPF)
  - Full IPv6 support (including dual-stack IPv4v6)

- ✅ **Extension Headers**
  - PDU Session Container (5G)
  - PDCP PDU Number
  - Long PDCP PDU Number
  - RAN Container
  - NR RAN Container
  - Service Class Indicator
  - UDP Port

### Advanced Features

- ✅ **Path Management**
  - Intelligent failure detection
  - RTT monitoring and statistics
  - Automatic failover support

- ✅ **QoS Flow Support (3GPP TS 23.501)**
  - Complete 5G QFI/5QI management
  - GBR and Non-GBR flows
  - Traffic classification
  - Delay budget tracking

- ✅ **Tunnel State Management**
  - Full state machine implementation
  - Lifecycle management
  - Anti-replay protection
  - Sequence number tracking

- ✅ **3GPP Compliance**
  - Cryptographic TEID generation
  - Wire format validation
  - Specification-driven validation

### Performance Optimizations

- ✅ **Memory Management**
  - Zero-copy operations
  - Memory pooling for packet buffers
  - Efficient buffer management

- ✅ **High Performance**
  - 10,000+ packets/second throughput
  - <1ms packet processing latency
  - 1,000+ concurrent session support
  - Batch processing support

- ✅ **Thread Safety**
  - Lock-free operations where possible
  - Thread-safe managers
  - Atomic reference counting

### Testing & Development

- ✅ **End-to-End Testing**
  - Mock gNodeB for traffic generation
  - Mock UPF for packet processing
  - Real-world 5G scenario simulation
  - Comprehensive statistics tracking

- ✅ **Test Coverage**
  - 3GPP compliance test suite
  - Wire format validation
  - Performance benchmarks
  - Integration tests

## Requirements

- Zig 0.14.1 or later
- Linux (for socket operations)

## Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/zig-gtp-u.git
cd zig-gtp-u

# Build the library and all executables (including mock-gnb and mock-upf)
zig build

# Run tests
zig build test

# Run benchmarks
zig build bench

# Run example
zig build run
```

The build process creates:
- **libgtpu.a** - Static library for integration
- **gtpu-example** - Example usage
- **gtpu-perf** - Performance benchmarks
- **mock-upf** - Mock User Plane Function for e2e testing
- **mock-gnb** - Mock gNodeB for e2e testing

## Quick Start

### Basic G-PDU Creation

```zig
const std = @import("std");
const gtpu = @import("gtpu");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Create a G-PDU message
    const payload = "Hello, 5G!";
    var gpdu = gtpu.GtpuMessage.createGpdu(allocator, 0x12345678, payload);
    defer gpdu.deinit();

    // Add PDU Session Container for 5G
    const pdu_container = gtpu.extension.ExtensionHeader{
        .pdu_session_container = .{
            .pdu_type = 1,  // Uplink
            .qfi = 9,       // QoS Flow Identifier
            .ppi = 0,
            .rqi = false,
        },
    };
    try gpdu.addExtensionHeader(pdu_container);

    // Encode to wire format
    var buffer = std.ArrayList(u8).init(allocator);
    defer buffer.deinit();
    try gpdu.encode(buffer.writer());

    std.debug.print("Encoded {} bytes\n", .{buffer.items.len});
}
```

### Session Management

```zig
const gtpu = @import("gtpu");

// Initialize managers
var tunnel_mgr = gtpu.TunnelManager.init(allocator);
defer tunnel_mgr.deinit();

var session_mgr = gtpu.SessionManager.init(allocator, &tunnel_mgr);
defer session_mgr.deinit();

// Create a PDU session (IPv4)
const local_addr = try std.net.Address.parseIp("192.168.1.1", 2152);
const remote_addr = try std.net.Address.parseIp("192.168.1.2", 2152);

try session_mgr.createSession(1, .ipv4, "internet", local_addr, remote_addr);

// Add QoS flow
if (session_mgr.getSession(1)) |session| {
    const qos_params = gtpu.qos.QosFlowParams{
        .qfi = 9,
        .fiveqi = .default_bearer,
        .arp = gtpu.qos.AllocationRetentionPriority.init(5),
    };
    try session.addQosFlow(qos_params);
    try session.activate();
}
```

### IPv6 and Dual-Stack Support

```zig
const gtpu = @import("gtpu");

// IPv6 session
const local_v6 = try std.net.Address.parseIp6("2001:db8::1", 2152);
const remote_v6 = try std.net.Address.parseIp6("2001:db8::2", 2152);

try session_mgr.createSession(2, .ipv6, "internet", local_v6, remote_v6);

// Dual-stack session (supports both IPv4 and IPv6)
try session_mgr.createSession(3, .ipv4v6, "internet", local_v6, remote_v6);

// PCAP capture works seamlessly with IPv6
var pcap = try gtpu.pcap.PcapWriter.init("ipv6_traffic.pcap");
defer pcap.deinit();

// Captures both IPv4 and IPv6 packets automatically
try pcap.writeUdpPacket(timestamp, local_v6, remote_v6, gtp_payload);
```

### Path Management with Echo

```zig
const gtpu = @import("gtpu");

// Configure path management
const config = gtpu.path.PathConfig{
    .echo_interval_ms = 60000,
    .echo_timeout_ms = 5000,
    .max_echo_failures = 3,
};

var path_mgr = gtpu.PathManager.init(allocator, config);
defer path_mgr.deinit();

// Get or create path
const peer_addr = try std.net.Address.parseIp("192.168.1.2", 2152);
const path = try path_mgr.getOrCreatePath(peer_addr);

// Check if echo is needed
const now = std.time.nanoTimestamp();
if (path.needsEcho(now)) {
    const sequence = path.sendEcho(now);
    // Send echo request with sequence number
}
```

### UPF Integration

The library provides comprehensive features for building User Plane Function (UPF) implementations. Here's a complete example showing how to process incoming GTP-U traffic with QoS flow handling:

```zig
const std = @import("std");
const gtpu = @import("gtpu");

pub fn processIncomingPacket(
    allocator: std.mem.Allocator,
    data: []const u8,
    qos_mgr: *gtpu.qos.QosFlowManager,
) !void {
    // Decode the GTP-U message
    var stream = std.io.fixedBufferStream(data);
    var msg = try gtpu.GtpuMessage.decode(allocator, stream.reader());
    defer msg.deinit();

    // Extract QFI directly using the helper method
    if (msg.getQFI()) |qfi| {
        std.debug.print("Processing packet with QFI: {}\n", .{qfi});

        // Route to appropriate QoS flow
        if (qos_mgr.getFlow(qfi)) |flow| {
            flow.stats.recordPacket(msg.payload.len, 1000, false);
        }
    }

    // Or get full PDU Session Container for detailed info
    if (msg.getPduSessionContainer()) |psc| {
        const direction = if (psc.pdu_type == 0) "Downlink" else "Uplink";
        std.debug.print("Direction: {s}, QFI: {}, RQI: {}\n", .{
            direction, psc.qfi, psc.rqi,
        });
    }
}
```

#### Handling Echo Requests/Responses

Proper echo handling is essential for path management. When receiving an echo response, update the path state:

```zig
fn handleEchoResponse(
    path_mgr: *gtpu.PathManager,
    peer_address: std.net.Address,
    sequence: u16,
) void {
    if (path_mgr.getPath(peer_address)) |path| {
        const current_time = std.time.nanoTimestamp();
        path.receiveEchoResponse(sequence, current_time) catch |err| {
            std.debug.print("Echo mismatch: {}\n", .{err});
        };

        // Check path health after echo
        const stats = path.getStats();
        std.debug.print("Path RTT: avg={}us, loss={d:.1}%\n", .{
            stats.avg_rtt_us,
            stats.packetLossRate() * 100,
        });
    }
}
```

#### Batch Processing for High-Throughput UPF

For high-performance scenarios, use the batch processing API:

```zig
const gtpu = @import("gtpu");

pub fn processBatch(allocator: std.mem.Allocator) !void {
    var batch = gtpu.pool.MessageBatch.init(allocator);
    defer batch.deinit();

    var stats = gtpu.pool.BatchStats{};

    // Add encoded messages to batch
    // (in practice, these come from network I/O)
    try batch.addEncoded(encoded_data_1, 0x12345678, 9);
    try batch.addEncoded(encoded_data_2, 0x87654321, 5);
    try batch.addEncoded(encoded_data_3, 0x12345678, 9);

    // Group by QFI for QoS-based processing
    var qfi_groups = try batch.groupByQFI(allocator);
    defer {
        var it = qfi_groups.valueIterator();
        while (it.next()) |list| list.deinit();
        qfi_groups.deinit();
    }

    // Process each QoS flow separately
    var qfi_it = qfi_groups.iterator();
    while (qfi_it.next()) |entry| {
        const qfi = entry.key_ptr.*;
        const messages = entry.value_ptr.items;
        std.debug.print("QFI {}: {} messages\n", .{ qfi, messages.len });
        // Apply QoS-specific processing...
    }

    // Or group by TEID for tunnel-based processing
    var teid_groups = try batch.groupByTEID(allocator);
    defer {
        var it = teid_groups.valueIterator();
        while (it.next()) |list| list.deinit();
        teid_groups.deinit();
    }

    // Track statistics
    stats.recordBatch(&batch);
    std.debug.print("Processed {} batches, {} messages, {} bytes\n", .{
        stats.batches_processed,
        stats.messages_processed,
        stats.bytes_processed,
    });
}
```

#### Complete UPF Example

See `tests/mock_upf.zig` for a complete UPF implementation demonstrating:
- Session management with uplink/downlink tunnels
- Echo request/response with RTT tracking
- QoS flow processing with QFI extraction
- Extension header handling
- PCAP capture for debugging
- Graceful shutdown with statistics

## Architecture

### Module Structure

```
src/
├── lib.zig              # Main library exports
├── protocol.zig         # Protocol constants and types
├── header.zig           # GTP-U header encoding/decoding
├── message.zig          # Message types and handling
├── ie.zig              # Information Elements
├── extension.zig        # Extension headers
├── tunnel.zig           # Tunnel management
├── session.zig          # PDU session management
├── path.zig            # Path management with RTT
├── qos.zig             # QoS flow support
├── pool.zig            # Memory pooling
└── utils.zig           # Utilities (TEID gen, anti-replay)

tests/
├── compliance_tests.zig    # 3GPP compliance tests
├── wire_format_tests.zig   # Wire format validation
├── performance_tests.zig   # Performance benchmarks
├── mock_upf.zig           # Mock UPF for e2e testing
└── mock_gnb.zig           # Mock gNB for e2e testing
```

## Testing

### Run All Tests

```bash
zig build test
```

### Run Compliance Tests

The compliance test suite validates adherence to 3GPP specifications:

```bash
zig test tests/compliance_tests.zig
```

### Run Performance Benchmarks

```bash
zig build bench
```

Expected performance on modern hardware:
- **Throughput**: 10,000+ packets/second
- **Latency**: <1ms per packet
- **Memory**: Efficient pooling with zero-copy
- **Scalability**: 1,000+ concurrent sessions

### End-to-End Testing

The project includes mock implementations of gNodeB and UPF for comprehensive end-to-end testing of the GTP-U protocol stack.

#### Mock Applications

**mock_upf** - Mock User Plane Function
- Receives uplink G-PDUs from gNodeB
- Processes QoS flows and extension headers
- Handles Echo Request/Response for path management
- Tracks comprehensive statistics

**mock_gnb** - Mock gNodeB (5G Base Station)
- Generates uplink traffic with configurable patterns
- Adds PDU Session Container extension headers with QFI
- Handles downlink G-PDUs from UPF
- Supports graceful shutdown with Ctrl+C

#### Running End-to-End Tests

**Terminal 1: Start Mock UPF**
```bash
# Build all mock applications
zig build

# Start mock UPF listening on port 2152
./zig-out/bin/mock-upf 0.0.0.0 2152

# Optional: Enable PCAP capture
./zig-out/bin/mock-upf 0.0.0.0 2152 upf-capture.pcap
```

**Terminal 2: Start Mock gNB**
```bash
# Start mock gNB, connecting to UPF at 127.0.0.1:2152
./zig-out/bin/mock-gnb 0.0.0.0 2153 127.0.0.1 2152

# Optional: Enable PCAP capture
./zig-out/bin/mock-gnb 0.0.0.0 2153 127.0.0.1 2152 gnb-capture.pcap
```

The mock gNB will automatically:
1. Establish a test PDU session
2. Send Echo Request to verify path to UPF
3. Generate uplink traffic (1 packet/sec, 1024 bytes by default)
4. Process downlink responses from UPF

Press **Ctrl+C** on either application to gracefully shutdown and view statistics.

**Example Output:**
```
=== Mock gNB Starting ===
Mock gNB listening on 0.0.0.0:2153
Mock gNB connected to UPF at 127.0.0.1:2152
Created test session 1 with TEID UL: 0x5A3C8F21, DL: 0x7B4D9E32
Sent Echo Request (seq: 1)
Started traffic generation: session=1, interval=1000ms, size=1024 bytes
Sent UL G-PDU (TEID: 0x5A3C8F21, 1024 bytes, QFI: 9)
Received Echo Response (seq: 1)
...
^C
Received Ctrl+C, shutting down gracefully...

=== Mock gNB Statistics ===
  Packets RX:    145
  Packets TX:    148
  Bytes RX:      58400
  Bytes TX:      151552
  Echo Req:      1
  Echo Resp:     1
  Uplink G-PDUs: 147
  Downlink G-PDUs: 144
  Errors:        0
```

#### E2E Test Architecture

```
┌─────────────┐                           ┌─────────────┐
│  mock_gnb   │                           │  mock_upf   │
│             │                           │             │
│ • Session   │    GTP-U (N3 Interface)   │ • Session   │
│   Mgmt      │◄─────────────────────────►│   Mgmt      │
│ • Traffic   │                           │ • QoS Flow  │
│   Gen       │   Uplink G-PDUs (QFI=9)   │   Process   │
│ • QoS       │──────────────────────────►│ • Stats     │
│   Mapping   │                           │   Tracking  │
│             │   Downlink G-PDUs         │             │
│ Port: 2153  │◄──────────────────────────│ Port: 2152  │
└─────────────┘                           └─────────────┘
```

#### Test Scenarios Covered

- ✅ PDU session establishment with uplink/downlink tunnels
- ✅ Echo Request/Response path management
- ✅ G-PDU encapsulation with PDU Session Container
- ✅ QoS Flow Identifier (QFI) mapping for 5G
- ✅ Extension header processing
- ✅ Statistics tracking (packets, bytes, errors)
- ✅ Graceful shutdown and cleanup

#### PCAP Capture for Wireshark

Both mock applications support optional PCAP capture for traffic analysis with Wireshark:

```bash
# Capture GTP-U traffic from mock gNB
./zig-out/bin/mock-gnb 0.0.0.0 2153 127.0.0.1 2152 gnb-traffic.pcap

# Capture GTP-U traffic from mock UPF
./zig-out/bin/mock-upf 0.0.0.0 2152 upf-traffic.pcap
```

The PCAP files contain:
- Complete UDP/IP/Ethernet encapsulation (IPv4 and IPv6)
- All GTP-U packets (Echo, G-PDU, End Marker, Error Indication)
- Precise timestamps for latency analysis
- Extension headers (PDU Session Container with QFI)
- Full IPv6 support with correct checksums

**Analyzing with Wireshark:**
```bash
# Open PCAP file in Wireshark
wireshark gnb-traffic.pcap

# Filter for GTP-U traffic
# Display filter: gtp
# Or by message type: gtp.message == 0xff (Echo) or gtp.message == 0x01 (G-PDU)
```

The PCAP capture enables:
- Protocol compliance verification
- Performance analysis (latency, throughput)
- Debugging extension headers and QoS flows
- Integration testing with other 5G components

## 3GPP Compliance

This implementation follows these 3GPP specifications:

- **TS 29.281 v18.0.0** - GTP-U Protocol
- **TS 23.501 v18.0.0** - 5G System Architecture
- **TS 29.244** - Interface between Control Plane and User Plane

### Validated Features

- ✅ Header format (Section 5.1)
- ✅ Message types (Section 7.1)
- ✅ Extension headers (Section 5.2)
- ✅ Path management (Section 4.4)
- ✅ Error handling (Section 7.3)
- ✅ 5G QoS flows (TS 23.501)

## Performance Characteristics

### Benchmarks

Measured on Intel i7-9700K @ 3.60GHz:

| Operation | Throughput | Latency |
|-----------|-----------|---------|
| G-PDU Encode | 150,000 ops/s | 6.7 µs |
| G-PDU Decode | 140,000 ops/s | 7.1 µs |
| Tunnel Lookup | 1,000,000 ops/s | 1.0 µs |
| Memory Pool | 2,000,000 ops/s | 0.5 µs |
| Session Create | 100,000 ops/s | 10 µs |

### Memory Usage

- Base library: ~50 KB
- Per tunnel: ~200 bytes
- Per session: ~400 bytes
- Packet buffer pool: Configurable (default: 1000 × 2048 bytes)

## Examples

See the `src/main.zig` for a comprehensive example covering:

- Session creation and management
- G-PDU message handling
- Echo request/response
- Extension headers
- QoS flow configuration
- Memory pool usage

## Development Setup

### Prerequisites

```bash
# Install Zig 0.14.1
curl https://ziglang.org/download/0.14.1/zig-linux-x86_64-0.14.1.tar.xz | tar -xJ
export PATH=$PATH:$PWD/zig-linux-x86_64-0.14.1

# Verify installation
zig version
```

### Build Options

```bash
# Debug build
zig build

# Release build (optimized)
zig build -Doptimize=ReleaseFast

# Release with safety checks
zig build -Doptimize=ReleaseSafe

# Small binary size
zig build -Doptimize=ReleaseSmall
```

## Contributing

Contributions are welcome! Please ensure:

1. All tests pass: `zig build test`
2. Code follows Zig style guidelines
3. 3GPP compliance is maintained
4. Performance benchmarks don't regress

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## References

- [3GPP TS 29.281](https://www.3gpp.org/DynaReport/29281.htm) - GTP-U Protocol
- [3GPP TS 23.501](https://www.3gpp.org/DynaReport/23501.htm) - 5G System Architecture
- [Zig Language](https://ziglang.org/) - Official Zig Documentation

## Roadmap

- [x] Mock gNodeB and UPF for end-to-end testing
- [x] PCAP file generation for Wireshark
- [x] IPv6 support enhancements (complete IPv6 + dual-stack)
- [ ] Additional 5G extension headers
- [ ] Integration with PFCP (N4 interface)
- [ ] Kubernetes deployment examples
- [ ] Prometheus metrics exporter

## Support

For issues, questions, or contributions:
- Open an issue on GitHub
- Check the examples in `src/main.zig`
- Review test cases for usage patterns

---

**Status**: Production-ready • **Version**: 0.1.0 • **Zig**: 0.14.1
