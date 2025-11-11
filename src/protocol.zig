// GTP-U Protocol Constants and Types
// 3GPP TS 29.281 v18.0.0

const std = @import("std");

// GTP-U version as per 3GPP TS 29.281
pub const GTPU_VERSION = 1;

// UDP port numbers
pub const GTPU_PORT = 2152;
pub const GTPU_CONTROL_PORT = 2123;

// Protocol Type
pub const GTP_PROTOCOL_TYPE = 1; // GTP'

// Maximum packet size
pub const MAX_GTPU_PACKET_SIZE = 65535;
pub const MAX_GTPU_PAYLOAD_SIZE = MAX_GTPU_PACKET_SIZE - 12; // Minus minimum header

// TEID values
pub const TEID_ZERO = 0x00000000; // Used for certain signaling messages

// Message Types as per 3GPP TS 29.281 Section 7.1
pub const MessageType = enum(u8) {
    // Echo messages
    echo_request = 1,
    echo_response = 2,

    // Error indication
    error_indication = 26,

    // Supported extension headers notification
    supported_extension_headers_notification = 31,

    // G-PDU (User Data)
    g_pdu = 255,

    // End marker
    end_marker = 254,

    _,

    pub fn isValid(self: MessageType) bool {
        return switch (self) {
            .echo_request, .echo_response, .error_indication, .supported_extension_headers_notification, .g_pdu, .end_marker => true,
            else => false,
        };
    }

    pub fn requiresTeid(self: MessageType) bool {
        return switch (self) {
            .g_pdu, .end_marker, .error_indication => true,
            .echo_request, .echo_response, .supported_extension_headers_notification => false,
            else => false,
        };
    }

    pub fn toString(self: MessageType) []const u8 {
        return switch (self) {
            .echo_request => "Echo Request",
            .echo_response => "Echo Response",
            .error_indication => "Error Indication",
            .supported_extension_headers_notification => "Supported Extension Headers Notification",
            .g_pdu => "G-PDU",
            .end_marker => "End Marker",
            else => "Unknown",
        };
    }
};

// Extension Header Types as per 3GPP TS 29.281 Section 5.2
pub const ExtensionHeaderType = enum(u8) {
    no_more_headers = 0x00,
    reserved = 0x01,

    // MBMS Support Indication (deprecated)
    mbms_support_indication = 0x02,

    // Service Class Indicator
    service_class_indicator = 0x20,

    // UDP Port
    udp_port = 0x40,

    // RAN Container
    ran_container = 0x81,

    // Long PDCP PDU Number
    long_pdcp_pdu_number = 0x82,

    // XW RAN Container
    xw_ran_container = 0x83,

    // NR RAN Container
    nr_ran_container = 0x84,

    // PDU Session Container
    pdu_session_container = 0x85,

    // Data Delivery Status (5G)
    dl_data_delivery_status = 0x86,
    ul_data_delivery_status = 0x87,

    // Delay Indication (5G)
    dl_delay = 0x88,
    ul_delay = 0x89,

    // Buffering Indication (5G)
    dl_buffering_suggested_packets_count = 0x8A,
    dl_buffering_duration = 0x8B,

    // Sending Time (5G)
    dl_sending_time = 0x8C,
    ul_sending_time = 0x8D,

    // PDCP PDU Number
    pdcp_pdu_number = 0xC0,

    // Suspend Request
    suspend_request = 0xC1,

    // Suspend Response
    suspend_response = 0xC2,

    _,

    pub fn isValid(self: ExtensionHeaderType) bool {
        return switch (self) {
            .no_more_headers,
            .service_class_indicator,
            .udp_port,
            .ran_container,
            .long_pdcp_pdu_number,
            .xw_ran_container,
            .nr_ran_container,
            .pdu_session_container,
            .dl_data_delivery_status,
            .ul_data_delivery_status,
            .dl_delay,
            .ul_delay,
            .dl_buffering_suggested_packets_count,
            .dl_buffering_duration,
            .dl_sending_time,
            .ul_sending_time,
            .pdcp_pdu_number,
            .suspend_request,
            .suspend_response => true,
            else => false,
        };
    }

    pub fn toString(self: ExtensionHeaderType) []const u8 {
        return switch (self) {
            .no_more_headers => "No More Headers",
            .service_class_indicator => "Service Class Indicator",
            .udp_port => "UDP Port",
            .ran_container => "RAN Container",
            .long_pdcp_pdu_number => "Long PDCP PDU Number",
            .xw_ran_container => "XW RAN Container",
            .nr_ran_container => "NR RAN Container",
            .pdu_session_container => "PDU Session Container",
            .dl_data_delivery_status => "DL Data Delivery Status",
            .ul_data_delivery_status => "UL Data Delivery Status",
            .dl_delay => "DL Delay",
            .ul_delay => "UL Delay",
            .dl_buffering_suggested_packets_count => "DL Buffering Suggested Packets Count",
            .dl_buffering_duration => "DL Buffering Duration",
            .dl_sending_time => "DL Sending Time",
            .ul_sending_time => "UL Sending Time",
            .pdcp_pdu_number => "PDCP PDU Number",
            .suspend_request => "Suspend Request",
            .suspend_response => "Suspend Response",
            else => "Unknown",
        };
    }
};

test "MessageType validation" {
    try std.testing.expect(MessageType.echo_request.isValid());
    try std.testing.expect(MessageType.g_pdu.isValid());
    try std.testing.expect(!MessageType.echo_request.requiresTeid());
    try std.testing.expect(MessageType.g_pdu.requiresTeid());
}

test "ExtensionHeaderType validation" {
    try std.testing.expect(ExtensionHeaderType.pdcp_pdu_number.isValid());
    try std.testing.expect(ExtensionHeaderType.ran_container.isValid());
    try std.testing.expect(ExtensionHeaderType.no_more_headers.isValid());
}
