const std = @import("std");

/// Eigenstaendiger Bau aus dem Manifest.
///
/// `zig build` erzeugt das Modul allein aus diesem Verzeichnis, ohne den Rest
/// von R4OS. Die Datei zeigt nur auf module.R4MF - Name, Klasse, Quellen,
/// Ziel, Imports und Metadaten stehen dort und nirgends sonst.
pub fn build(b: *std.Build) void {
    const sdk_build = b.lazyImport(@This(), "r4os_sdk") orelse return;
    const sdk_dep = b.dependencyFromBuildZig(sdk_build, .{});
    const sdk = sdk_build.sdk(b, sdk_dep, .{});
    const dns = b.dependency("r4os_protocol_netdns", .{});
    _ = sdk.addR4MFWithOptions(b.path("module.R4MF"), .{
        .zig_module_roots = &.{dns.path("src/address_codec.zig")},
    });
    const tests = b.addTest(.{ .root_module = b.createModule(.{ .root_source_file = b.path("src/resolvers.zig"), .target = b.graph.host, .optimize = .ReleaseSafe }) });
    b.step("test", "Run ordered resolver literal and configuration boundary cases").dependOn(&b.addRunArtifact(tests).step);
}
