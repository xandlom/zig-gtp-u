// GTP-U Protocol Implementation for 5G Networks
// 3GPP TS 29.281 - GTP-U Protocol specification
// 3GPP TS 23.501 - 5G System Architecture

const std = @import("std");

pub const protocol = @import("protocol.zig");
pub const header = @import("header.zig");
pub const message = @import("message.zig");
pub const ie = @import("ie.zig");
pub const extension = @import("extension.zig");
pub const tunnel = @import("tunnel.zig");
pub const path = @import("path.zig");
pub const qos = @import("qos.zig");
pub const session = @import("session.zig");
pub const pool = @import("pool.zig");
pub const utils = @import("utils.zig");
pub const pcap = @import("pcap.zig");

// Re-export commonly used types
pub const GtpuHeader = header.GtpuHeader;
pub const MessageType = message.MessageType;
pub const GtpuMessage = message.GtpuMessage;
pub const Tunnel = tunnel.Tunnel;
pub const TunnelManager = tunnel.TunnelManager;
pub const PathManager = path.PathManager;
pub const QosFlow = qos.QosFlow;
pub const SessionManager = session.SessionManager;

// Version information
pub const version = std.SemanticVersion{
    .major = 0,
    .minor = 1,
    .patch = 0,
};

test {
    std.testing.refAllDecls(@This());
}
