const std = @import("std");
const rocca = @import("rocca.zig");
const RoccaS = rocca.RoccaS;

pub fn main() !void {
    const stdout_file = std.fs.File.stdout().deprecatedWriter();
    var bw = std.io.bufferedWriter(stdout_file);
    const stdout = bw.writer();

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
        var enc_timer = try std.time.Timer.start();
        var i: usize = 0;
        while (i < iterations) : (i += 1) {
            RoccaS.encrypt(ciphertext, &tag, message, associated_data, nonce, key);
        }
        const enc_time = enc_timer.read();

        // Benchmark decryption
        var dec_timer = try std.time.Timer.start();
        i = 0;
        while (i < iterations) : (i += 1) {
            try RoccaS.decrypt(message, ciphertext, tag, associated_data, nonce, key);
        }
        const dec_time = dec_timer.read();

        // Calculate throughput in bits/second
        const enc_throughput = (@as(f64, @floatFromInt(size * iterations * 8)) * 1_000_000_000.0) / @as(f64, @floatFromInt(enc_time));
        const dec_throughput = (@as(f64, @floatFromInt(size * iterations * 8)) * 1_000_000_000.0) / @as(f64, @floatFromInt(dec_time));

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
        try stdout.print("  Encryption: {d:.2} {s} ({d} iterations in {d:.2} ms)\n", .{ enc_display[0], enc_display[1], iterations, @as(f64, @floatFromInt(enc_time)) / 1_000_000.0 });
        try stdout.print("  Decryption: {d:.2} {s} ({d} iterations in {d:.2} ms)\n", .{ dec_display[0], dec_display[1], iterations, @as(f64, @floatFromInt(dec_time)) / 1_000_000.0 });
        try stdout.print("\n", .{});
    }

    try bw.flush();
}
