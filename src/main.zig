const std = @import("std");
const assert = std.debug.assert;
const crypto = std.crypto;
const fmt = std.fmt;
const mem = std.mem;
const AesBlock = std.crypto.core.aes.Block;
const AuthenticationError = std.crypto.errors.AuthenticationError;

const State = struct {
    blocks: [7]AesBlock,
    k0: AesBlock,
    k1: AesBlock,

    const rounds = 16;

    fn init(key: [RoccaS.key_length]u8, nonce: [RoccaS.nonce_length]u8) State {
        const z0 = AesBlock.fromBytes(&[_]u8{ 205, 101, 239, 35, 145, 68, 55, 113, 34, 174, 40, 215, 152, 47, 138, 66 });
        const z1 = AesBlock.fromBytes(&[_]u8{ 188, 219, 137, 129, 165, 219, 181, 233, 47, 59, 77, 236, 207, 251, 192, 181 });
        const k0 = AesBlock.fromBytes(key[0..16]);
        const k1 = AesBlock.fromBytes(key[16..32]);
        const zero = AesBlock.fromBytes(&([_]u8{0} ** 16));
        const nonce_block = AesBlock.fromBytes(&nonce);

        const blocks = [7]AesBlock{
            k1,
            nonce_block,
            z0,
            k0,
            z1,
            nonce_block.xorBlocks(k1),
            zero,
        };
        var state = State{ .blocks = blocks, .k0 = k0, .k1 = k1 };
        var i: usize = 0;
        while (i < rounds) : (i += 1) {
            state.update(z0, z1);
        }
        return state;
    }

    inline fn update(state: *State, x0: AesBlock, x1: AesBlock) void {
        const blocks = &state.blocks;
        const next: [7]AesBlock = .{
            blocks[6].xorBlocks(blocks[1]),
            blocks[0].encrypt(x0),
            blocks[1].encrypt(blocks[0]),
            blocks[2].encrypt(blocks[6]),
            blocks[3].encrypt(x1),
            blocks[4].encrypt(blocks[3]),
            blocks[5].encrypt(blocks[4]),
        };
        state.blocks = next;
    }

    fn enc(state: *State, dst: *[32]u8, src: *const [32]u8) void {
        const blocks = &state.blocks;
        const msg0 = AesBlock.fromBytes(src[0..16]);
        const msg1 = AesBlock.fromBytes(src[16..32]);
        const tmp0 = blocks[3].xorBlocks(blocks[5]).encrypt(blocks[0]).xorBlocks(msg0);
        const tmp1 = blocks[4].xorBlocks(blocks[6]).encrypt(blocks[2]).xorBlocks(msg1);
        dst[0..16].* = tmp0.toBytes();
        dst[16..32].* = tmp1.toBytes();
        state.update(msg0, msg1);
    }

    fn dec(state: *State, dst: *[32]u8, src: *const [32]u8) void {
        const blocks = &state.blocks;
        const c0 = AesBlock.fromBytes(src[0..16]);
        const c1 = AesBlock.fromBytes(src[16..32]);
        const msg0 = blocks[3].xorBlocks(blocks[5]).encrypt(blocks[0]).xorBlocks(c0);
        const msg1 = blocks[4].xorBlocks(blocks[6]).encrypt(blocks[2]).xorBlocks(c1);
        dst[0..16].* = msg0.toBytes();
        dst[16..32].* = msg1.toBytes();
        state.update(msg0, msg1);
    }

    fn decPartial(state: *State, dst: []u8, src: *const [32]u8) void {
        const blocks = &state.blocks;
        const c0 = AesBlock.fromBytes(src[0..16]);
        const c1 = AesBlock.fromBytes(src[16..32]);
        const msg0 = blocks[3].xorBlocks(blocks[5]).encrypt(blocks[0]).xorBlocks(c0);
        const msg1 = blocks[4].xorBlocks(blocks[6]).encrypt(blocks[2]).xorBlocks(c1);
        var padded: [32]u8 = undefined;
        padded[0..16].* = msg0.toBytes();
        padded[16..32].* = msg1.toBytes();
        mem.set(u8, padded[dst.len..], 0);
        mem.copy(u8, dst, padded[0..dst.len]);
        state.update(AesBlock.fromBytes(padded[0..16]), AesBlock.fromBytes(padded[16..32]));
    }

    fn mac(state: *State, adlen: usize, mlen: usize) [32]u8 {
        var blocks = &state.blocks;
        blocks[1] = blocks[1].xorBlocks(state.k0);
        blocks[2] = blocks[2].xorBlocks(state.k1);
        var adlen_bytes: [16]u8 = undefined;
        var mlen_bytes: [16]u8 = undefined;
        mem.writeIntLittle(u128, &adlen_bytes, adlen * 8);
        mem.writeIntLittle(u128, &mlen_bytes, mlen * 8);
        const adlen_block = AesBlock.fromBytes(&adlen_bytes);
        const mlen_block = AesBlock.fromBytes(&mlen_bytes);
        var i: usize = 0;
        while (i < rounds) : (i += 1) {
            state.update(adlen_block, mlen_block);
        }
        var tag: [32]u8 = undefined;
        tag[0..16].* = blocks[0].xorBlocks(blocks[1]).xorBlocks(blocks[2]).xorBlocks(blocks[3]).toBytes();
        tag[16..32].* = blocks[4].xorBlocks(blocks[5]).xorBlocks(blocks[6]).toBytes();
        return tag;
    }
};

/// ROCCA-S is a very fast authenticated encryption system built on top of the core AES function.
///
/// It has a 256 bit key, a 128 bit nonce, and processes 256 bit message blocks.
/// It was designed to fully exploit the parallelism and built-in AES support of recent Intel and ARM CPUs.
///
/// https://www.ietf.org/archive/id/draft-nakano-rocca-s-01.html
pub const RoccaS = struct {
    pub const tag_length = 32;
    pub const nonce_length = 16;
    pub const key_length = 32;

    /// c: ciphertext: output buffer should be of size m.len
    /// tag: authentication tag: output MAC
    /// m: message
    /// ad: Associated Data
    /// npub: public nonce
    /// k: private key
    pub fn encrypt(c: []u8, tag: *[tag_length]u8, m: []const u8, ad: []const u8, npub: [nonce_length]u8, key: [key_length]u8) void {
        assert(c.len == m.len);
        var state = State.init(key, npub);
        var src: [32]u8 align(16) = undefined;
        var dst: [32]u8 align(16) = undefined;
        var i: usize = 0;
        while (i + 32 <= ad.len) : (i += 32) {
            state.enc(&dst, ad[i..][0..32]);
        }
        if (ad.len % 32 != 0) {
            mem.set(u8, src[0..], 0);
            mem.copy(u8, src[0 .. ad.len % 32], ad[i .. i + ad.len % 32]);
            state.enc(&dst, &src);
        }
        i = 0;
        while (i + 32 <= m.len) : (i += 32) {
            state.enc(c[i..][0..32], m[i..][0..32]);
        }
        if (m.len % 32 != 0) {
            mem.set(u8, src[0..], 0);
            mem.copy(u8, src[0 .. m.len % 32], m[i .. i + m.len % 32]);
            state.enc(&dst, &src);
            mem.copy(u8, c[i .. i + m.len % 32], dst[0 .. m.len % 32]);
        }
        tag.* = state.mac(ad.len, m.len);
    }

    /// m: message: output buffer should be of size c.len
    /// c: ciphertext
    /// tag: authentication tag
    /// ad: Associated Data
    /// npub: public nonce
    /// k: private key
    pub fn decrypt(m: []u8, c: []const u8, tag: [tag_length]u8, ad: []const u8, npub: [nonce_length]u8, key: [key_length]u8) AuthenticationError!void {
        assert(c.len == m.len);
        var state = State.init(key, npub);
        var src: [32]u8 align(16) = undefined;
        var dst: [32]u8 align(16) = undefined;
        var i: usize = 0;
        while (i + 32 <= ad.len) : (i += 32) {
            state.enc(&dst, ad[i..][0..32]);
        }
        if (ad.len % 32 != 0) {
            mem.set(u8, src[0..], 0);
            mem.copy(u8, src[0 .. ad.len % 32], ad[i .. i + ad.len % 32]);
            state.enc(&dst, &src);
        }
        i = 0;
        while (i + 32 <= m.len) : (i += 32) {
            state.dec(m[i..][0..32], c[i..][0..32]);
        }
        if (m.len % 32 != 0) {
            mem.set(u8, src[0..], 0);
            mem.copy(u8, src[0 .. m.len % 32], c[i .. i + m.len % 32]);
            state.decPartial(m[i .. i + m.len % 32], &src);
        }
        const computed_tag = state.mac(ad.len, m.len);
        var acc: u8 = 0;
        for (computed_tag) |_, j| {
            acc |= (computed_tag[j] ^ tag[j]);
        }
        if (acc != 0) {
            mem.set(u8, m, 0xaa);
            return error.AuthenticationFailed;
        }
    }
};

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
    mem.set(u8, m[0..], 0x41);

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
    _ = try fmt.hexToBytes(&expected_tag, "8c6e84a97d9c729a1d291bafae1fe82aca97fd9b3a80256a4d57a18bd3d15951");
    var expected_c: [m.len]u8 = undefined;
    _ = try fmt.hexToBytes(&expected_c, "6f983ab45ff43b83d91b0c393b91df3d339fc7811568af8bdbc6c3fa02519caa9514054c70bd4c45ea047ac196f880d19025fbbea500c83bf484acc396c36193");
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
    _ = try fmt.hexToBytes(&expected_tag, "80adbd5b4d3913d0e4b6938c5bac3cc20d67a85e0a93e6f92ecfe5f328ae44ff");
    var expected_c: [m.len]u8 = undefined;
    _ = try fmt.hexToBytes(&expected_c, "8638fdd10710982215671146036e9f74bc15c4279de4f8d983c376dd5a8908a1ef5b5aceabaaa7e8e7d4db8119e206ec215172bed7dfeb5ad5501a6b33f5b94b");
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
    _ = try fmt.hexToBytes(&expected_tag, "3fe3ca4f00b8e0f3f5cf049454678439fae5ff079c863ccc0948513e21d2409d");
    var expected_c: [m.len]u8 = undefined;
    _ = try fmt.hexToBytes(&expected_c, "8627c5771a07ea4e5bdb278c81e97da7d56fbb0870c04e93ffc273ac8015b9d6dbacd40417a4512c9e49cea2d4844f53ee1c862e8b742cf8c4cd30569d5b563d");
    RoccaS.encrypt(&m, &tag, &m, &ad, nonce, key);
    try testing.expectEqualSlices(u8, &tag, &expected_tag);
    try testing.expectEqualSlices(u8, &m, &expected_c);
}
