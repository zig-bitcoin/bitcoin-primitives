const std = @import("std");
const mem = std.mem;
const Hash = std.crypto.hash.sha2.Sha256;

/// Unfinalized output of the SHA256 hash function.
///
/// The `Midstate` type is obscure and specialized and should not be used unless you are sure of
/// what you are doing.
///
/// It represents "partially hashed data" but does not itself have properties of cryptographic
/// hashes. For example, when (ab)used as hashes, midstates are vulnerable to trivial
/// length-extension attacks. They are typically used to optimize the computation of full hashes.
/// For example, when implementing BIP-340 tagged hashes, which always begin by hashing the same
/// fixed 64-byte prefix, it makes sense to hash the prefix once, store the midstate as a constant,
/// and hash any future data starting from the constant rather than from a fresh hash engine.
///
/// For BIP-340 support we provide the [`sha256t`] module, and the [`sha256t_tag`] macro which will
/// create the midstate for you in const context.
const Midstate = struct {
    /// Raw bytes of the midstate i.e., the already-hashed contents of the hash engine.
    data: [32]u8,
    /// Number of bytes hashed to achieve this midstate.
    // INVARIANT must always be a multiple of 64.
    length: u64,

    pub fn asBytes(self: Midstate) [8]u32 {
        var blocks: [8]u32 = undefined;
        var idx: usize = 0;
        var idxBuff: usize = 0;
        while (idx < 8) : (idx += 1) {
            blocks[idx] = std.mem.readInt(u32, @ptrCast(&self.data[idxBuff]), .big);
            idxBuff += 4;
        }
        return blocks;
    }

    /// Creates midstate for tagged hashes.
    ///
    /// Computes non-finalized hash of `sha256(tag) || sha256(tag)` for use in [`sha256t`]. It's
    /// provided for use with [`sha256t`].
    pub fn hash_tag(tag: []const u8) Midstate {
        var h = Hash.init(.{});
        h.update(tag);
        const hash = h.finalResult();

        var buf: [64]u8 = undefined;
        for (&buf, 0..) |*buf_elem, idx| {
            buf_elem.* = hash[idx % 32];
        }

        var h2 = Hash.init(.{});
        h2.update(&buf);

        var blocks: [32]u8 = undefined;
        for (h2.s, 0..) |word, idx| {
            const idx4 = idx * 4;
            blocks[idx4] = @truncate(word >> 24);
            blocks[idx4 + 1] = @truncate(word >> 16);
            blocks[idx4 + 2] = @truncate(word >> 8);
            blocks[idx4 + 3] = @truncate(word);
        }

        return Midstate{ .data = blocks, .length = h2.total_len };
    }
};

const BLOCK_SIZE: usize = 64;

/// Engine to compute SHA256 hash function.
const HashEngine = struct {
    buffer: [BLOCK_SIZE]u8,
    h: [8]u32,
    length: u64,

    /// Creates a new SHA256 hash engine.
    pub fn new() HashEngine {
        return HashEngine{
            .buffer = std.mem.zeroes([BLOCK_SIZE]u8),
            .h = [8]u32{
                0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
            },
            .length = 0,
        };
    }

    /// Creates a new [`HashEngine`] from a [`Midstate`].
    ///
    /// Please see docs on [`Midstate`] before using this function.
    pub fn fromMidstate(midstate: Midstate) HashEngine {
        const midstate_bytes = midstate.asBytes();

        return HashEngine{
            .buffer = std.mem.zeroes([BLOCK_SIZE]u32),
            .h = midstate_bytes,
            .length = midstate.length,
        };
    }

    // TODO: need `input` compatible in rust implementation
    // pub fn update(self: *HashEngine, data: []const u8) void {
    //     var sha = Hash.init(.{});
    //     sha.update(data);
    //     self.h = sha.s;
    // }

    pub fn getMidstate(self: *HashEngine) Midstate {
        var midstate_bytes: [32]u8 = undefined;
        for (self.h, 0..) |word, idx| {
            const idx4 = idx * 4;
            midstate_bytes[idx4] = @truncate(word >> 24);
            midstate_bytes[idx4 + 1] = @truncate(word >> 16);
            midstate_bytes[idx4 + 2] = @truncate(word >> 8);
            midstate_bytes[idx4 + 3] = @truncate(word);
        }
        return Midstate{ .data = midstate_bytes, .length = self.length };
    }
};

test "Convert [32]u8 to [8]u32" {
    const input: [32]u8 = [32]u8{
        0x0f, 0xd0, 0x69, 0x0c, 0xfe, 0xfe, 0xae, 0xb7,
        0x99, 0x6e, 0xac, 0x7f, 0x5c, 0x30, 0xd8, 0x64,
        0x8c, 0x4a, 0x05, 0x73, 0xac, 0xa1, 0xa2, 0x2f,
        0x6f, 0x43, 0xb8, 0x01, 0x85, 0xce, 0x27, 0xcd,
    };

    var midstate = Midstate{
        .data = input,
        .length = 32,
    };

    const expected: [8]u32 = [8]u32{
        0x0fd0690c, 0xfefeaeb7, 0x996eac7f, 0x5c30d864,
        0x8c4a0573, 0xaca1a22f, 0x6f43b801, 0x85ce27cd,
    };

    const result = midstate.asBytes();
    try std.testing.expectEqualSlices(u32, &expected, &result);
}

test "const midstate" {
    const expectedMidstate = Midstate{
        .data = [32]u8{
            156, 224, 228, 230, 124, 17, 108, 57,  56, 179, 202, 242, 195, 15,  80, 137, 211, 243,
            147, 108, 71,  99,  110, 96, 125, 179, 62, 234, 221, 198, 240, 201,
        },
        .length = 64,
    };

    const midstate = Midstate.hash_tag("TapLeaf");

    try std.testing.expectEqualSlices(u8, &expectedMidstate.data, &midstate.data);

    try std.testing.expectEqual(expectedMidstate.length, midstate.length);
}

// TODO make it work
// test "midstate" {
//     // Test vector obtained by doing an asset issuance on Elements
//     var engine = HashEngine.new();
//     // sha256dhash of outpoint
//     // 73828cbc65fd68ab78dc86992b76ae50ae2bf8ceedbe8de0483172f0886219f7:0
//     const input1: [32]u8 = [32]u8{
//         0x9d, 0xd0, 0x1b, 0x56, 0xb1, 0x56, 0x45, 0x14,
//         0x3e, 0xad, 0x15, 0x8d, 0xec, 0x19, 0xf8, 0xce,
//         0xa9, 0x0b, 0xd0, 0xa9, 0xb2, 0xf8, 0x1d, 0x21,
//         0xff, 0xa3, 0xa4, 0xc6, 0x44, 0x81, 0xd4, 0x1c,
//     };
//     engine.update(&input1);
//     // 32 bytes of zeroes representing "new asset"
//     const input2: [32]u8 = std.mem.zeroes([32]u8);
//     engine.update(&input2);

//     // RPC output
//     const WANT = Midstate{
//         .data = [32]u8{
//             0x0b, 0xcf, 0xe0, 0xe5, 0x4e, 0x6c, 0xc7, 0xd3,
//             0x4f, 0x4f, 0x7c, 0x1d, 0xf0, 0xb0, 0xf5, 0x03,
//             0xf2, 0xf7, 0x12, 0x91, 0x2a, 0x06, 0x05, 0xb4,
//             0x14, 0xed, 0x33, 0x7f, 0x7f, 0x03, 0x2e, 0x03,
//         },
//         .length = 64,
//     };

//     // get midstate
//     const computed_midstate = engine.getMidstate();

//     try std.testing.expectEqualSlices(u8, &WANT.data, &computed_midstate.data);
//     try std.testing.expectEqual(WANT.length, computed_midstate.length);

//     std.debug.print("Test passed: Midstate matches expected value.\n", .{});
// }
