# Architecture Documentation

## Overview

zig-gtp-u is a high-performance GTP-U implementation designed for 5G networks. The architecture follows a modular design with clear separation of concerns.

## Design Principles

1. **Zero-Copy**: Minimize data copying through efficient buffer management
2. **Thread-Safe**: All managers are thread-safe with minimal lock contention
3. **3GPP Compliant**: Strict adherence to specifications
4. **Performance**: Optimized for high throughput and low latency
5. **Memory Efficient**: Pooling and careful resource management

## Component Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     Application Layer                        │
├─────────────────────────────────────────────────────────────┤
│              Session Manager (PDU Sessions)                  │
├─────────────────────────────────────────────────────────────┤
│   Tunnel Manager  │  Path Manager   │   QoS Flow Manager   │
├─────────────────────────────────────────────────────────────┤
│          Message Encoding/Decoding (GTP-U Protocol)         │
├─────────────────────────────────────────────────────────────┤
│  Memory Pool  │  Utilities  │  Extension Headers  │  IEs   │
├─────────────────────────────────────────────────────────────┤
│                    Network Layer (UDP)                       │
└─────────────────────────────────────────────────────────────┘
```

## Core Components

### Protocol Layer (`protocol.zig`, `header.zig`)

**Responsibilities:**
- Define GTP-U constants and types
- Header encoding/decoding
- Wire format handling

**Key Types:**
- `MessageType`: GTP-U message types (Echo, G-PDU, etc.)
- `ExtensionHeaderType`: Extension header types
- `GtpuHeader`: GTP-U header structure

**Performance:**
- Zero-allocation header parsing
- Efficient big-endian conversion
- Minimal validation overhead

### Message Layer (`message.zig`)

**Responsibilities:**
- Message creation and parsing
- Extension header management
- Information element handling

**Key Types:**
- `GtpuMessage`: Complete GTP-U message
- Helper functions for common message types

**Design:**
- Builder pattern for message construction
- Automatic length calculation
- Support for arbitrary extension headers

### Tunnel Management (`tunnel.zig`)

**Responsibilities:**
- Tunnel lifecycle management
- State machine implementation
- Statistics tracking
- Anti-replay protection

**Key Types:**
- `Tunnel`: Individual tunnel with state
- `TunnelManager`: Thread-safe tunnel registry
- `TunnelState`: State machine enum

**Thread Safety:**
- Per-tunnel mutex for state changes
- Lock-free TEID allocation
- Atomic statistics

### Session Management (`session.zig`)

**Responsibilities:**
- PDU session lifecycle
- Multi-tunnel coordination
- QoS flow association

**Key Types:**
- `PduSession`: 5G PDU session
- `SessionManager`: Session registry
- `PduSessionType`: Session type enum

**Design:**
- Session owns multiple tunnels (UL/DL)
- Integrated QoS flow management
- Automatic tunnel creation

### Path Management (`path.zig`)

**Responsibilities:**
- Path failure detection
- RTT monitoring
- Echo mechanism

**Key Types:**
- `Path`: Peer path with statistics
- `PathManager`: Path registry
- `PathState`: Health state enum

**Features:**
- Configurable timeouts
- Automatic failover
- Statistical tracking (min/max/avg RTT)

### QoS Flow Support (`qos.zig`)

**Responsibilities:**
- 5G QoS flow management
- Traffic classification
- Delay budget tracking

**Key Types:**
- `QosFlow`: Individual QoS flow
- `QosFlowParams`: Flow parameters
- `QosCharacteristics`: 5QI definitions

**Compliance:**
- Full 3GPP TS 23.501 support
- GBR/Non-GBR flows
- Priority handling

### Memory Pool (`pool.zig`)

**Responsibilities:**
- Zero-copy buffer management
- Memory pooling
- Batch processing

**Key Types:**
- `MemoryPool(T)`: Generic memory pool
- `PacketBufferPool`: Packet-specific pool
- `BatchProcessor`: Batch operations

**Performance:**
- Lock-free fast path (when possible)
- Reference counting
- Aligned allocations

### Utilities (`utils.zig`)

**Responsibilities:**
- TEID generation
- Anti-replay protection
- Rate limiting
- Checksums

**Key Types:**
- `TeidGenerator`: Cryptographic TEID generation
- `AntiReplayWindow`: Sliding window implementation
- `RateLimiter`: Token bucket algorithm
- `CircularBuffer(T)`: Generic ring buffer

## Data Flow

### Packet Transmission (TX)

```
Application
    │
    ├─> Create Message (GtpuMessage)
    │
    ├─> Add Extension Headers
    │
    ├─> Add Payload
    │
    ├─> Encode to Buffer
    │       │
    │       ├─> Encode Header (8-12 bytes)
    │       ├─> Encode Extensions (variable)
    │       └─> Copy Payload
    │
    └─> Send via UDP Socket
```

### Packet Reception (RX)

```
UDP Socket
    │
    ├─> Receive into Buffer
    │
    ├─> Decode Message
    │       │
    │       ├─> Parse Header
    │       ├─> Parse Extensions
    │       └─> Extract Payload
    │
    ├─> Lookup Tunnel (by TEID)
    │
    ├─> Validate Sequence
    │
    ├─> Process QoS Flow
    │
    └─> Deliver to Application
```

## Threading Model

### Thread Safety Guarantees

1. **Managers**: All manager types are thread-safe
   - `TunnelManager`
   - `SessionManager`
   - `PathManager`
   - `QosFlowManager`

2. **Statistics**: Atomic counters for all statistics

3. **Memory Pools**: Thread-safe acquire/release

### Lock Hierarchy

To prevent deadlocks, locks must be acquired in this order:

1. SessionManager
2. TunnelManager
3. PathManager
4. Individual objects (Tunnel, Path, etc.)

## Memory Management

### Allocation Strategy

1. **Stack Allocation**: Small, fixed-size objects
2. **Pool Allocation**: Packet buffers
3. **Heap Allocation**: Dynamic collections (lists, maps)

### Lifetime Management

- **Messages**: Caller owns and must deinit
- **Tunnels**: Managed by TunnelManager
- **Sessions**: Managed by SessionManager
- **Buffers**: Reference counted via pool

## Performance Optimizations

### Zero-Copy Paths

1. **Buffer Sharing**: Reference counting instead of copying
2. **Slice Operations**: Work on slices without allocation
3. **In-Place Encoding**: Direct writes to output buffer

### Lock-Free Operations

1. **TEID Allocation**: Atomic counter
2. **Statistics**: Atomic updates
3. **Reference Counting**: Atomic operations

### Cache Efficiency

1. **Struct Packing**: Minimize padding
2. **Hot/Cold Split**: Separate frequently/rarely accessed data
3. **Alignment**: Natural alignment for atomic operations

## Error Handling

### Error Categories

1. **Protocol Errors**: Invalid wire format
2. **State Errors**: Invalid state transitions
3. **Resource Errors**: Out of memory/buffers
4. **Network Errors**: Socket operations

### Error Propagation

- Use Zig's error union types
- Detailed error types for debugging
- Graceful degradation where possible

## Testing Strategy

### Unit Tests

- Per-module test coverage
- Focus on edge cases
- Property-based testing where applicable

### Integration Tests

- Multi-component scenarios
- State machine validation
- Error path testing

### Compliance Tests

- 3GPP specification validation
- Wire format verification
- Golden packet tests

### Performance Tests

- Throughput benchmarks
- Latency measurements
- Scalability tests
- Memory usage profiling

## Future Enhancements

### Completed Features

1. ✅ **PCAP Support**: Wireshark integration with full packet capture

### Planned Features

1. **Metrics Export**: Prometheus/OpenTelemetry
2. **IPv6**: Enhanced IPv6 support
3. **PFCP Integration**: N4 interface support

### Performance Improvements

1. **SIMD**: Vectorized operations
2. **io_uring**: Linux async I/O
3. **DPDK**: Kernel bypass option
4. **eBPF**: XDP fast path

## Configuration

### Tuning Parameters

```zig
// Path management
const path_config = PathConfig{
    .echo_interval_ms = 60000,
    .echo_timeout_ms = 5000,
    .max_echo_failures = 3,
    .suspect_threshold_ms = 10000,
};

// Memory pools
const pool_config = PoolConfig{
    .buffer_count = 1000,
    .buffer_size = 2048,
};

// QoS parameters
const qos_params = QosFlowParams{
    .packet_delay_budget = 100,  // ms
    .packet_error_rate = 3,      // 10^-3
    .averaging_window = 2000,    // ms
};
```

## Deployment Considerations

### Production Guidelines

1. **Buffer Sizing**: Match MTU and expected traffic
2. **Pool Capacity**: Size for peak load + margin
3. **Thread Count**: CPU cores for packet processing
4. **Monitoring**: Track statistics continuously

### Resource Limits

- **Memory**: ~50KB base + pools + tunnels
- **CPU**: Scales with packet rate
- **Network**: Standard UDP sockets

---

This architecture provides a solid foundation for high-performance 5G user plane processing while maintaining 3GPP compliance and code clarity.
