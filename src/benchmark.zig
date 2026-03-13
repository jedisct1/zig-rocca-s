const std = @import("std");
const Io = std.Io;
const rocca = @import("rocca.zig");
const RoccaS = rocca.RoccaS;

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    var stdout_buffer: [4096]u8 = undefined;
    var stdout_file_writer: Io.File.Writer = .init(.stdout(), io, &stdout_buffer);
    const stdout = &stdout_file_writer.interface;

    const key = [_]u8{0} ** 32;
    const nonce = [_]u8{0} ** 16;
    const associated_data = "benchmark associated data";

    const sizes = [_]usize{ 64, 256, 1024, 4096, 16384, 65536 };

    const allocator = std.heap.page_allocator;

    try stdout.print("ROCCA-S Benchmark\n", .{});
    try stdout.print("=================\n\n", .{});

    for (sizes) |size| {
        const message = try allocator.alloc(u8, size);
        defer allocator.free(message);
        const ciphertext = try allocator.alloc(u8, size);
        defer allocator.free(ciphertext);

        @memset(message, 0x42);

        var tag: [RoccaS.tag_length]u8 = undefined;

        const iterations: usize = if (size <= 1024) 100000 else if (size <= 16384) 10000 else 1000;

        // Benchmark encryption
        const enc_start = Io.Timestamp.now(io, .awake);
        var i: usize = 0;
        while (i < iterations) : (i += 1) {
            RoccaS.encrypt(ciphertext, &tag, message, associated_data, nonce, key);
        }
        const enc_end = Io.Timestamp.now(io, .awake);
        const enc_time = enc_start.durationTo(enc_end).nanoseconds;

        // Benchmark decryption
        const dec_start = Io.Timestamp.now(io, .awake);
        i = 0;
        while (i < iterations) : (i += 1) {
            try RoccaS.decrypt(message, ciphertext, tag, associated_data, nonce, key);
        }
        const dec_end = Io.Timestamp.now(io, .awake);
        const dec_time = dec_start.durationTo(dec_end).nanoseconds;

        // Calculate throughput in bits/second
        const total_bits: f64 = @floatFromInt(size * iterations * 8);
        const enc_ns: f64 = @floatFromInt(enc_time);
        const dec_ns: f64 = @floatFromInt(dec_time);
        const enc_throughput = total_bits * 1_000_000_000.0 / enc_ns;
        const dec_throughput = total_bits * 1_000_000_000.0 / dec_ns;

        // Format throughput with appropriate units (Mbps or Gbps)
        const enc_display = if (enc_throughput >= 1_000_000_000.0)
            .{ enc_throughput / 1_000_000_000.0, "Gbps" }
        else
            .{ enc_throughput / 1_000_000.0, "Mbps" };

        const dec_display = if (dec_throughput >= 1_000_000_000.0)
            .{ dec_throughput / 1_000_000_000.0, "Gbps" }
        else
            .{ dec_throughput / 1_000_000.0, "Mbps" };

        try stdout.print("Size: {d} bytes\n", .{size});
        try stdout.print("  Encryption: {d:.2} {s} ({d} iterations in {d:.2} ms)\n", .{ enc_display[0], enc_display[1], iterations, enc_ns / 1_000_000.0 });
        try stdout.print("  Decryption: {d:.2} {s} ({d} iterations in {d:.2} ms)\n", .{ dec_display[0], dec_display[1], iterations, dec_ns / 1_000_000.0 });
        try stdout.print("\n", .{});
    }

    try stdout.flush();
}
