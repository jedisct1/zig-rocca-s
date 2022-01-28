const std = @import("std");
const assert = std.debug.assert;
const crypto = std.crypto;
const fmt = std.fmt;
const mem = std.mem;
const AesBlock = std.crypto.core.aes.Block;
const AuthenticationError = std.crypto.errors.AuthenticationError;

const State = struct {
    blocks: [8]AesBlock,

    const rounds = 20;

    fn init(key: [Rocca.key_length]u8, nonce: [Rocca.nonce_length]u8) State {
        const z0 = AesBlock.fromBytes(&[_]u8{ 205, 101, 239, 35, 145, 68, 55, 113, 34, 174, 40, 215, 152, 47, 138, 66 });
        const z1 = AesBlock.fromBytes(&[_]u8{ 188, 219, 137, 129, 165, 219, 181, 233, 47, 59, 77, 236, 207, 251, 192, 181 });
        const k0 = AesBlock.fromBytes(key[0..16]);
        const k1 = AesBlock.fromBytes(key[16..32]);
        const zero = AesBlock.fromBytes(&([_]u8{0} ** 16));
        const nonce_block = AesBlock.fromBytes(&nonce);

        const blocks = [8]AesBlock{
            k1,
            nonce_block,
            z0,
            z1,
            nonce_block.xorBlocks(k1),
            zero,
            k0,
            zero,
        };
        var state = State{ .blocks = blocks };
        var i: usize = 0;
        while (i < rounds) : (i += 1) {
            state.update(z0, z1);
        }
        return state;
    }

    inline fn update(state: *State, x0: AesBlock, x1: AesBlock) void {
        const blocks = &state.blocks;
        const next: [8]AesBlock = .{
            blocks[7].xorBlocks(x0),
            blocks[0].encrypt(blocks[7]),
            blocks[1].xorBlocks(blocks[6]),
            blocks[2].encrypt(blocks[1]),
            blocks[3].xorBlocks(x1),
            blocks[4].encrypt(blocks[3]),
            blocks[5].encrypt(blocks[4]),
            blocks[0].xorBlocks(blocks[6]),
        };
        state.blocks = next;
    }

    fn enc(state: *State, dst: *[32]u8, src: *const [32]u8) void {
        const blocks = &state.blocks;
        const msg0 = AesBlock.fromBytes(src[0..16]);
        const msg1 = AesBlock.fromBytes(src[16..32]);
        const tmp0 = blocks[1].encrypt(blocks[5]).xorBlocks(msg0);
        const tmp1 = blocks[0].xorBlocks(blocks[4]).encrypt(blocks[2]).xorBlocks(msg1);
        dst[0..16].* = tmp0.toBytes();
        dst[16..32].* = tmp1.toBytes();
        state.update(msg0, msg1);
    }

    fn dec(state: *State, dst: *[32]u8, src: *const [32]u8) void {
        const blocks = &state.blocks;
        const c0 = AesBlock.fromBytes(src[0..16]);
        const c1 = AesBlock.fromBytes(src[16..32]);
        const msg0 = blocks[1].encrypt(blocks[5]).xorBlocks(c0);
        const msg1 = blocks[0].xorBlocks(blocks[4]).encrypt(blocks[2]).xorBlocks(c1);
        dst[0..16].* = msg0.toBytes();
        dst[16..32].* = msg1.toBytes();
        state.update(msg0, msg1);
    }

    fn decPartial(state: *State, dst: []u8, src: *const [32]u8) void {
        const blocks = &state.blocks;
        const c0 = AesBlock.fromBytes(src[0..16]);
        const c1 = AesBlock.fromBytes(src[16..32]);
        const msg0 = blocks[1].encrypt(blocks[5]).xorBlocks(c0);
        const msg1 = blocks[0].xorBlocks(blocks[4]).encrypt(blocks[2]).xorBlocks(c1);
        var padded: [32]u8 = undefined;
        padded[0..16].* = msg0.toBytes();
        padded[16..32].* = msg1.toBytes();
        mem.set(u8, padded[dst.len..], 0);
        mem.copy(u8, dst, padded[0..dst.len]);
        state.update(AesBlock.fromBytes(padded[0..16]), AesBlock.fromBytes(padded[16..32]));
    }

    fn mac(state: *State, adlen: usize, mlen: usize) [16]u8 {
        const blocks = &state.blocks;
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
        return blocks[0].xorBlocks(blocks[1]).xorBlocks(blocks[2]).xorBlocks(blocks[3])
            .xorBlocks(blocks[4]).xorBlocks(blocks[5]).xorBlocks(blocks[6]).xorBlocks(blocks[7])
            .toBytes();
    }
};

/// ROCCA is a very fast authenticated encryption system built on top of the core AES function.
///
/// It has a 256 bit key, a 128 bit nonce, and processes 256 bit message blocks.
/// It was designed to fully exploit the parallelism and built-in AES support of recent Intel and ARM CPUs.
///
/// https://tosc.iacr.org/index.php/ToSC/article/download/8904/8480/
pub const Rocca = struct {
    pub const tag_length = 16;
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
    var tag: [Rocca.tag_length]u8 = undefined;
    var expected_tag: [Rocca.tag_length]u8 = undefined;
    _ = try fmt.hexToBytes(&expected_tag, "2ee37e014157fa6a24c80f13996c77bb");
    Rocca.encrypt(&c, &tag, "", "", nonce, key);
    try testing.expectEqualSlices(u8, &tag, &expected_tag);
}

test "basic test" {
    const key = [_]u8{0} ** 32;
    const nonce = [_]u8{0} ** 16;
    const mlen = 1000;
    var tag: [Rocca.tag_length]u8 = undefined;

    const allocator = std.testing.allocator;
    var m = try allocator.alloc(u8, mlen);
    defer allocator.free(m);
    mem.set(u8, m[0..], 0x41);

    Rocca.encrypt(m[0..], &tag, m[0..], "associated data", nonce, key);
    try Rocca.decrypt(m[0..], m[0..], tag, "associated data", nonce, key);

    for (m) |x| {
        try testing.expectEqual(x, 0x41);
    }
}

test "test vector 1" {
    const key = [_]u8{0} ** 32;
    const nonce = [_]u8{0} ** 16;
    const ad = [_]u8{0} ** 32;
    var m = [_]u8{0} ** 64;
    var tag: [Rocca.tag_length]u8 = undefined;
    var expected_tag: [Rocca.tag_length]u8 = undefined;
    _ = try fmt.hexToBytes(&expected_tag, "cc728c8baedd36f14cf8938e9e0719bf");
    var expected_c: [m.len]u8 = undefined;
    _ = try fmt.hexToBytes(&expected_c, "15892f8555ad2db4749b90926571c4b8c28b434f277793c53833cb6e41a855291784a2c7fe374b34d875fdcbe84f5b88bf3f386f2218f046a84318565026d755");
    Rocca.encrypt(&m, &tag, &m, &ad, nonce, key);
    try testing.expectEqualSlices(u8, &tag, &expected_tag);
    try testing.expectEqualSlices(u8, &m, &expected_c);
}

test "test vector 2" {
    const key = [_]u8{1} ** 32;
    const nonce = [_]u8{1} ** 16;
    const ad = [_]u8{1} ** 32;
    var m = [_]u8{0} ** 64;
    var tag: [Rocca.tag_length]u8 = undefined;
    var expected_tag: [Rocca.tag_length]u8 = undefined;
    _ = try fmt.hexToBytes(&expected_tag, "bad0a53616599bfdb553788fdaabad78");
    var expected_c: [m.len]u8 = undefined;
    _ = try fmt.hexToBytes(&expected_c, "f931a8730b2e8a3af341c83a29c30525325c170326c29d91b24d714fecf385fd88e650ef2e2c02b37b19e70bb93ff82aa96d50c9fdf05343f6e36b66ee7bda69");
    Rocca.encrypt(&m, &tag, &m, &ad, nonce, key);
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
    var tag: [Rocca.tag_length]u8 = undefined;
    var expected_tag: [Rocca.tag_length]u8 = undefined;
    _ = try fmt.hexToBytes(&expected_tag, "6672534a8b57c287bcf56823cd1cdb5a");
    var expected_c: [m.len]u8 = undefined;
    _ = try fmt.hexToBytes(&expected_c, "265b7e314141fd148235a5305b217ab291a2a7aeff91efd3ac603b28e0576109723422ef3f553b0b07ce7263f63502a00591de648f3ee3b05441d8313b138b5a");
    Rocca.encrypt(&m, &tag, &m, &ad, nonce, key);
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
    var tag: [Rocca.tag_length]u8 = undefined;
    var expected_tag: [Rocca.tag_length]u8 = undefined;
    _ = try fmt.hexToBytes(&expected_tag, "a9f2069456559de3e69d233e154ba05e");
    var expected_c: [m.len]u8 = undefined;
    _ = try fmt.hexToBytes(&expected_c, "d9b3361abb733958fa2830b8ec374e2835c5d29aae867efbd4f6a874cc24c6c66acab1020ac2344b3eb78efe54b5a0b6f19d1bea7dbf47f1d6c966a04a3e7692");
    Rocca.encrypt(&m, &tag, &m, &ad, nonce, key);
    try testing.expectEqualSlices(u8, &tag, &expected_tag);
    try testing.expectEqualSlices(u8, &m, &expected_c);
}
