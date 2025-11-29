# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build Commands

```bash
# Build library and all executables
zig build

# Run tests (includes unit, compliance, and wire format tests)
zig build test

# Run performance benchmarks
zig build bench

# Run example
zig build run

# Build with optimization
zig build -Doptimize=ReleaseFast    # Maximum performance
zig build -Doptimize=ReleaseSafe    # Performance with safety checks
zig build -Doptimize=ReleaseSmall   # Minimize binary size
```

## Test Commands

```bash
# Run all tests
zig build test

# Run specific test files
zig test tests/compliance_tests.zig
zig test tests/wire_format_tests.zig
zig test src/lib.zig  # Unit tests

# Run mock applications for end-to-end testing
./zig-out/bin/mock-upf 0.0.0.0 2152 [optional-pcap-file.pcap]
./zig-out/bin/mock-gnb 0.0.0.0 2153 127.0.0.1 2152 [optional-pcap-file.pcap]
```

## Architecture Overview

This is a high-performance GTP-U (GPRS Tunneling Protocol User Plane) implementation for 5G networks, compliant with 3GPP TS 29.281 and TS 23.501.

### Module Hierarchy

The codebase follows a layered architecture (bottom to top):

1. **Protocol Foundation** (`protocol.zig`, `header.zig`)
   - Wire format definitions, constants, and header encoding/decoding
   - Zero-allocation parsing with efficient big-endian conversion

2. **Message Layer** (`message.zig`, `ie.zig`, `extension.zig`)
   - `GtpuMessage`: Complete message abstraction with builder pattern
   - Extension headers: PDU Session Container, PDCP PDU Number, RAN Container, etc.
   - Helper methods: `getQFI()`, `getPduSessionContainer()` for QoS flow extraction

3. **Management Layer** (`tunnel.zig`, `session.zig`, `path.zig`, `qos.zig`)
   - `TunnelManager`: Thread-safe tunnel lifecycle and state machine
   - `SessionManager`: PDU session management with uplink/downlink tunnels
   - `PathManager`: Path failure detection, RTT monitoring, Echo mechanism
   - `QosFlowManager`: 5G QoS flow management with 5QI characteristics

4. **Performance Layer** (`pool.zig`, `utils.zig`)
   - `MemoryPool(T)`: Generic memory pooling with reference counting
   - `PacketBufferPool`: Zero-copy buffer management
   - `MessageBatch`: Batch processing with QFI/TEID grouping
   - `TeidGenerator`: Cryptographic TEID generation
   - `AntiReplayWindow`: Sliding window for sequence number validation

5. **Utilities** (`pcap.zig`)
   - PCAP file writing for Wireshark analysis with full IPv4/IPv6 support

### Thread Safety Model

All manager types are thread-safe:
- `TunnelManager`, `SessionManager`, `PathManager`, `QosFlowManager`
- Lock hierarchy (acquire in this order to prevent deadlocks): SessionManager → TunnelManager → PathManager → Individual objects
- Atomic statistics counters throughout
- Lock-free operations for TEID allocation and reference counting

### Key Data Flow Patterns

**Packet TX**: Application → Create GtpuMessage → Add Extension Headers → Encode to Buffer → UDP Socket

**Packet RX**: UDP Socket → Decode Message → Lookup Tunnel (by TEID) → Validate Sequence → Process QoS Flow → Deliver

**Echo Path Management**: PathManager tracks per-peer RTT statistics, automatic failover on failures (configurable timeout/retry)

## Important Implementation Details

### Extension Header Processing

Extension headers use a linked-list chain in wire format. When adding multiple extension headers to a message, they must be properly chained:
- Each extension header contains a `next_type` field
- The last extension header has `next_type = 0` (no more extensions)
- Common extension headers: PDU Session Container (type 0x85) for 5G QFI

### QoS Flow Extraction

To extract QFI from incoming packets:
```zig
// Direct QFI extraction
if (msg.getQFI()) |qfi| {
    // Use qfi value
}

// Full PDU Session Container access
if (msg.getPduSessionContainer()) |psc| {
    const qfi = psc.qfi;
    const direction = if (psc.pdu_type == 0) "Downlink" else "Uplink";
}
```

### Echo Request/Response Handling

Echo mechanism is critical for path management:
- Echo requests use TEID 0x00000000 (special signaling TEID)
- Sequence numbers must match between request and response
- Path RTT tracking: `path.receiveEchoResponse(sequence, timestamp)` updates statistics
- Failed echo attempts tracked for automatic failover

### TEID Management

- TEIDs generated cryptographically via `TeidGenerator` for security
- TEID 0 reserved for signaling (Echo, Error Indication)
- Tunnels looked up by TEID, thread-safe via `TunnelManager.getTunnel(teid)`
- Each PDU session has separate uplink/downlink TEIDs

### Session States and Transitions

Tunnel states (in `tunnel.zig`):
- `inactive` → `activating` → `active` → `suspended` → `inactive`
- `active` → `failed` (on errors)
- State transitions protected by per-tunnel mutex

PDU Session states (in `session.zig`):
- `inactive` → `active` → `suspended` → `released`

### Memory Management

- **Messages**: Caller owns and must call `.deinit()` after use
- **Buffers**: Reference counted via pool - acquire/release pattern
- **Tunnels/Sessions**: Managed by their respective managers, automatic cleanup
- Stack allocation for small fixed-size objects, pool for packet buffers, heap for dynamic collections

### IPv6 Support

Full dual-stack IPv4/IPv6 support:
- Session types: `.ipv4`, `.ipv6`, `.ipv4v6`
- PCAP writer handles both protocols automatically
- UDP checksum calculation follows RFC 2460 for IPv6

## 3GPP Compliance Notes

This implementation strictly follows 3GPP specifications:
- **TS 29.281 v18.0.0**: GTP-U Protocol (message formats, extension headers)
- **TS 23.501 v18.0.0**: 5G System Architecture (QoS flows, PDU sessions)
- Wire format validation in `tests/wire_format_tests.zig`
- Compliance test suite in `tests/compliance_tests.zig`

### Common Message Types

- `g_pdu (255)`: User data tunneling
- `echo_request (1)` / `echo_response (2)`: Path management
- `error_indication (26)`: Error reporting
- `end_marker (254)`: Handover indication
- `supported_extension_headers_notification (31)`: Capability notification

## Performance Characteristics

Expected performance on modern hardware (Intel i7-9700K):
- **G-PDU Encode**: 150,000 ops/s (6.7 µs latency)
- **G-PDU Decode**: 140,000 ops/s (7.1 µs latency)
- **Tunnel Lookup**: 1,000,000 ops/s (1.0 µs latency)
- **Throughput**: 10,000+ packets/second
- **Latency**: <1ms packet processing
- **Scalability**: 1,000+ concurrent sessions

Memory usage:
- Base library: ~50 KB
- Per tunnel: ~200 bytes
- Per session: ~400 bytes
- Packet buffer pool: Configurable (default: 1000 × 2048 bytes)

## Development Patterns

### Creating a G-PDU with 5G QoS

```zig
var gpdu = gtpu.GtpuMessage.createGpdu(allocator, teid, payload);
defer gpdu.deinit();

const pdu_container = gtpu.extension.ExtensionHeader{
    .pdu_session_container = .{
        .pdu_type = 1,  // Uplink
        .qfi = 9,       // QoS Flow Identifier
        .ppi = 0,
        .rqi = false,
    },
};
try gpdu.addExtensionHeader(pdu_container);

var buffer = std.ArrayList(u8).init(allocator);
defer buffer.deinit();
try gpdu.encode(buffer.writer());
```

### Setting up Session Management

```zig
var tunnel_mgr = gtpu.TunnelManager.init(allocator);
defer tunnel_mgr.deinit();

var session_mgr = gtpu.SessionManager.init(allocator, &tunnel_mgr);
defer session_mgr.deinit();

// Create session with IPv4/IPv6/IPv4v6
try session_mgr.createSession(1, .ipv4, "internet", local_addr, remote_addr);

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

### Batch Processing for High Throughput

```zig
var batch = gtpu.pool.MessageBatch.init(allocator);
defer batch.deinit();

// Add messages to batch
try batch.addEncoded(data1, teid1, qfi1);
try batch.addEncoded(data2, teid2, qfi2);

// Group by QFI for QoS-based processing
var qfi_groups = try batch.groupByQFI(allocator);
defer {
    var it = qfi_groups.valueIterator();
    while (it.next()) |list| list.deinit();
    qfi_groups.deinit();
}

// Or group by TEID for tunnel-based processing
var teid_groups = try batch.groupByTEID(allocator);
// ... process groups ...
```

## Code Style

- Follow Zig standard library conventions
- Use meaningful variable names (avoid abbreviations except standard telecom terms: TEID, QFI, PDU, etc.)
- Prefer stack allocation over heap when possible
- Always provide `deinit()` methods for types that allocate
- Document 3GPP specification references for protocol-level code
- Use atomic operations for statistics that may be accessed concurrently
