//! Ordered resolver configuration. Literal decoding uses Zig's pure parser;
//! scopes are R4OS numeric interface identities, never host interface names.
const std = @import("std");
pub const Error = error{ Invalid, Capacity };
pub const Endpoint = struct { family: u16, bytes: [16]u8 = @splat(0), port: u16 = 53, scope: u32 = 0, interface: u32 = 0 };
pub const List = struct { count: usize = 0, entries: [8]Endpoint = undefined };
pub fn endpoint(text: []const u8) Error!Endpoint {
    if (text.len == 0) return error.Invalid;
    if (text[0] == '[') {
        const end = std.mem.findScalar(u8, text, ']') orelse return error.Invalid;
        var literal = text[1..end];
        var port: u16 = 53;
        if (end + 1 < text.len) {
            if (text[end + 1] != ':') return error.Invalid;
            port = std.fmt.parseInt(u16, text[end + 2 ..], 10) catch return error.Invalid;
        }
        if (port == 0) return error.Invalid;
        var scope: u32 = 0;
        if (std.mem.findScalar(u8, literal, '%')) |percent| {
            scope = std.fmt.parseInt(u32, literal[percent + 1 ..], 10) catch return error.Invalid;
            if (scope == 0) return error.Invalid;
            literal = literal[0..percent];
        }
        const parsed = switch (std.Io.net.Ip6Address.Unresolved.parse(literal)) {
            .success => |value| value,
            else => return error.Invalid,
        };
        if (parsed.interface_name != null or std.mem.allEqual(u8, &parsed.bytes, 0) or parsed.bytes[0] == 0xff or std.mem.eql(u8, parsed.bytes[0..12], &.{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff })) return error.Invalid;
        const ll = parsed.bytes[0] == 0xfe and parsed.bytes[1] & 0xc0 == 0x80;
        if (ll != (scope != 0)) return error.Invalid;
        return .{ .family = 6, .bytes = parsed.bytes, .port = port, .scope = scope, .interface = scope };
    }
    var literal = text;
    var port: u16 = 53;
    if (std.mem.findScalar(u8, text, ':')) |colon| {
        literal = text[0..colon];
        port = std.fmt.parseInt(u16, text[colon + 1 ..], 10) catch return error.Invalid;
    }
    const parsed = std.Io.net.Ip4Address.parse(literal, port) catch return error.Invalid;
    if (port == 0 or std.mem.allEqual(u8, &parsed.bytes, 0) or parsed.bytes[0] >= 224) return error.Invalid;
    var value: Endpoint = .{ .family = 4, .port = port };
    @memcpy(value.bytes[0..4], &parsed.bytes);
    return value;
}
pub fn parse(input: []const u8) Error!List {
    if (input.len > 4096) return error.Capacity;
    var list: List = .{};
    var lines = std.mem.splitScalar(u8, if (std.mem.startsWith(u8, input, "\xef\xbb\xbf")) input[3..] else input, '\n');
    while (lines.next()) |raw| {
        const line = std.mem.trim(u8, raw, " \t\r");
        if (line.len == 0 or line[0] == '#' or line[0] == ';') continue;
        const equal = std.mem.findScalar(u8, line, '=') orelse return error.Invalid;
        if (!std.ascii.eqlIgnoreCase(std.mem.trim(u8, line[0..equal], " \t"), "SERVER")) return error.Invalid;
        const value = try endpoint(std.mem.trim(u8, line[equal + 1 ..], " \t"));
        if (list.count == list.entries.len) return error.Capacity;
        for (list.entries[0..list.count]) |old| if (old.family == value.family and old.port == value.port and old.scope == value.scope and std.mem.eql(u8, &old.bytes, &value.bytes)) return error.Invalid;
        list.entries[list.count] = value;
        list.count += 1;
    }
    return list;
}
test "ordered IPv4 IPv6 and exact numeric link scope" {
    const list = try parse("\xef\xbb\xbf# sample\nSERVER=192.0.2.53\r\nSERVER=[2001:db8::53]:5353\nSERVER=[fe80::53%7]\n");
    try std.testing.expectEqual(@as(usize, 3), list.count);
    try std.testing.expectEqual(@as(u16, 4), list.entries[0].family);
    try std.testing.expectEqual(@as(u16, 5353), list.entries[1].port);
    try std.testing.expectEqual(@as(u32, 7), list.entries[2].scope);
    try std.testing.expectEqual(@as(u8, 0x53), list.entries[2].bytes[15]);
}
test "bad scopes mapped addresses partial records and oversized lists reject wholly" {
    for ([_][]const u8{ "[fe80::1]", "[fe80::1%0]", "[fe80::1%eno1]", "[2001:db8::1%2]", "[::ffff:192.0.2.1]", "[::]", "[ff02::1%1]", "[2001:db8::1]:0", "[2001:db8::1]:65536", "192.0.2.001", "0.0.0.0", "SERVER=1.2.3.4" }) |text| try std.testing.expectError(error.Invalid, endpoint(text));
    try std.testing.expectError(error.Invalid, parse("SERVER=192.0.2.1\nSERVER=bad\n"));
    try std.testing.expectError(error.Invalid, parse("SERVER=[2001:db8::1]\nSERVER=[2001:db8:0:0:0:0:0:1]\n"));
    try std.testing.expectError(error.Capacity, parse("SERVER=192.0.2.1\nSERVER=192.0.2.2\nSERVER=192.0.2.3\nSERVER=192.0.2.4\nSERVER=192.0.2.5\nSERVER=192.0.2.6\nSERVER=192.0.2.7\nSERVER=192.0.2.8\nSERVER=192.0.2.9\n"));
}
