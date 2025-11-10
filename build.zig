const std = @import("std");

pub fn build(b: *std.Build) void {
    // Target and optimization options
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // Main GTP-U library
    const gtpu_lib = b.addStaticLibrary(.{
        .name = "gtpu",
        .root_source_file = b.path("src/lib.zig"),
        .target = target,
        .optimize = optimize,
    });
    b.installArtifact(gtpu_lib);

    // Create module for the library
    const gtpu_module = b.addModule("gtpu", .{
        .root_source_file = b.path("src/lib.zig"),
    });

    // Example executable
    const example_exe = b.addExecutable(.{
        .name = "gtpu-example",
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });
    example_exe.root_module.addImport("gtpu", gtpu_module);
    b.installArtifact(example_exe);

    // Run step for example
    const run_cmd = b.addRunArtifact(example_exe);
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        run_cmd.addArgs(args);
    }
    const run_step = b.step("run", "Run the GTP-U example");
    run_step.dependOn(&run_cmd.step);

    // Unit tests
    const lib_unit_tests = b.addTest(.{
        .root_source_file = b.path("src/lib.zig"),
        .target = target,
        .optimize = optimize,
    });
    const run_lib_unit_tests = b.addRunArtifact(lib_unit_tests);

    // Compliance tests
    const compliance_tests = b.addTest(.{
        .root_source_file = b.path("tests/compliance_tests.zig"),
        .target = target,
        .optimize = optimize,
    });
    compliance_tests.root_module.addImport("gtpu", gtpu_module);
    const run_compliance_tests = b.addRunArtifact(compliance_tests);

    // Wire format tests
    const wire_tests = b.addTest(.{
        .root_source_file = b.path("tests/wire_format_tests.zig"),
        .target = target,
        .optimize = optimize,
    });
    wire_tests.root_module.addImport("gtpu", gtpu_module);
    const run_wire_tests = b.addRunArtifact(wire_tests);

    // Performance tests
    const perf_tests = b.addExecutable(.{
        .name = "gtpu-perf",
        .root_source_file = b.path("tests/performance_tests.zig"),
        .target = target,
        .optimize = .ReleaseFast,
    });
    perf_tests.root_module.addImport("gtpu", gtpu_module);
    b.installArtifact(perf_tests);

    // Test step
    const test_step = b.step("test", "Run all tests");
    test_step.dependOn(&run_lib_unit_tests.step);
    test_step.dependOn(&run_compliance_tests.step);
    test_step.dependOn(&run_wire_tests.step);

    // Benchmark step
    const bench_cmd = b.addRunArtifact(perf_tests);
    const bench_step = b.step("bench", "Run performance benchmarks");
    bench_step.dependOn(b.getInstallStep());
    bench_step.dependOn(&bench_cmd.step);

    // MockUPF executable
    const mock_upf = b.addExecutable(.{
        .name = "mock-upf",
        .root_source_file = b.path("tests/mock_upf.zig"),
        .target = target,
        .optimize = optimize,
    });
    mock_upf.root_module.addImport("gtpu", gtpu_module);
    b.installArtifact(mock_upf);
}
