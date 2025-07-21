const std = @import("std");
const fmt = std.fmt;
const rocca = @import("rocca.zig");
const RoccaS = rocca.RoccaS;

const testing = std.testing;

test "empty test" {
    const key = [_]u8{0} ** 32;
    const nonce = [_]u8{0} ** 16;
    var c = [_]u8{};
    var tag: [RoccaS.tag_length]u8 = undefined;
    var expected_tag: [RoccaS.tag_length]u8 = undefined;
    _ = try fmt.hexToBytes(&expected_tag, "d70bfa63d7658fb527b6c6ceb43f11b1696044eb4dbd9d3db83de552b61551b0");
    RoccaS.encrypt(&c, &tag, "", "", nonce, key);
    try testing.expectEqualSlices(u8, &tag, &expected_tag);
}

test "basic test" {
    const key = [_]u8{0} ** 32;
    const nonce = [_]u8{0} ** 16;
    const mlen = 1000;
    var tag: [RoccaS.tag_length]u8 = undefined;

    const allocator = std.testing.allocator;
    var m = try allocator.alloc(u8, mlen);
    defer allocator.free(m);
    @memset(m[0..], 0x41);

    RoccaS.encrypt(m[0..], &tag, m[0..], "associated data", nonce, key);
    try RoccaS.decrypt(m[0..], m[0..], tag, "associated data", nonce, key);

    for (m) |x| {
        try testing.expectEqual(x, 0x41);
    }
}

test "test vector 1" {
    const key = [_]u8{0} ** 32;
    const nonce = [_]u8{0} ** 16;
    const ad = [_]u8{0} ** 32;
    var m = [_]u8{0} ** 64;
    var tag: [RoccaS.tag_length]u8 = undefined;
    var expected_tag: [RoccaS.tag_length]u8 = undefined;
    _ = try fmt.hexToBytes(&expected_tag, "8df934d1483710c9410f6a089c4ced9791901b7e2e661206202db2cc7a24a386");
    var expected_c: [m.len]u8 = undefined;
    _ = try fmt.hexToBytes(&expected_c, "9ac3326495a8d414fe407f47b54410502481cf79cab8c0a669323e07711e46170de5b2fbba0fae8de7c1fccaeefc362624fcfdc15f8bb3e64457e8b7e37557bb");
    RoccaS.encrypt(&m, &tag, &m, &ad, nonce, key);
    try testing.expectEqualSlices(u8, &tag, &expected_tag);
    try testing.expectEqualSlices(u8, &m, &expected_c);
}

test "test vector 2" {
    const key = [_]u8{1} ** 32;
    const nonce = [_]u8{1} ** 16;
    const ad = [_]u8{1} ** 32;
    var m = [_]u8{0} ** 64;
    var tag: [RoccaS.tag_length]u8 = undefined;
    var expected_tag: [RoccaS.tag_length]u8 = undefined;
    _ = try fmt.hexToBytes(&expected_tag, "c1fdf39762eca77da8b0f1dae5fff75a92fb0adfa7940a28c8cadbbbe8e4ca8d");
    var expected_c: [m.len]u8 = undefined;
    _ = try fmt.hexToBytes(&expected_c, "559ecb253bcfe26b483bf00e9c748345978ff921036a6c1fdcb712172836504fbc64d430a73fc67acd3c3b9c1976d80790f48357e7fe0c0682624569d3a658fb");
    RoccaS.encrypt(&m, &tag, &m, &ad, nonce, key);
    try testing.expectEqualSlices(u8, &tag, &expected_tag);
    try testing.expectEqualSlices(u8, &m, &expected_c);
}

test "test vector 3" {
    var key: [32]u8 = undefined;
    _ = try fmt.hexToBytes(&key, "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
    var nonce: [16]u8 = undefined;
    _ = try fmt.hexToBytes(&nonce, "0123456789abcdef0123456789abcdef");
    var ad: [32]u8 = undefined;
    _ = try fmt.hexToBytes(&ad, "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
    var m = [_]u8{0} ** 64;
    var tag: [RoccaS.tag_length]u8 = undefined;
    var expected_tag: [RoccaS.tag_length]u8 = undefined;
    _ = try fmt.hexToBytes(&expected_tag, "a078e1351ef2420c8e3a93fd31f5b1135b15315a5f205534148efbcd63f79f00");
    var expected_c: [m.len]u8 = undefined;
    _ = try fmt.hexToBytes(&expected_c, "b5fc4e2a72b86d1a133c0f0202bdf790af14a24b2cdb676e427865e12fcc9d3021d18418fc75dc1912dd2cd79a3beeb2a98b235de2299b9dda93fd2b5ac8f436");
    RoccaS.encrypt(&m, &tag, &m, &ad, nonce, key);
    try testing.expectEqualSlices(u8, &tag, &expected_tag);
    try testing.expectEqualSlices(u8, &m, &expected_c);
}

test "test vector 4" {
    const key = [_]u8{0x11} ** 16 ++ [_]u8{0x22} ** 16;
    const nonce = [_]u8{0x44} ** 16;
    var ad: [18]u8 = undefined;
    _ = try fmt.hexToBytes(&ad, "808182838485868788898a8b8c8d8e8f9091");
    var m: [64]u8 = undefined;
    _ = try fmt.hexToBytes(&m, "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f");
    var tag: [RoccaS.tag_length]u8 = undefined;
    var expected_tag: [RoccaS.tag_length]u8 = undefined;
    _ = try fmt.hexToBytes(&expected_tag, "e16bae2feff540be2b4ce999d440bc730b7e332e25b6ce4e1a9785b95f6eb1cd");
    var expected_c: [m.len]u8 = undefined;
    _ = try fmt.hexToBytes(&expected_c, "e28d9f86288f77115d4ef620e7cedecee4d7de0fce38a9061f813c9805bc1ea7fdf6709eabcfcf75801649edc063579ea08cc645f5197c7ded9c99115775369f");
    RoccaS.encrypt(&m, &tag, &m, &ad, nonce, key);
    try testing.expectEqualSlices(u8, &tag, &expected_tag);
    try testing.expectEqualSlices(u8, &m, &expected_c);
}
