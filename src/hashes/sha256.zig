const std = @import("std");
const mem = std.mem;

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
            blocks[idx] = @as(u32, self.data[idxBuff]) << 24 | @as(u24, self.data[idxBuff + 1]) << 16 | @as(u16, self.data[idxBuff + 2]) << 8 | self.data[idxBuff + 3];
            idxBuff += 4;
        }
        return blocks;
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

    const result = midstate.asChunkedBytes();
    try std.testing.expectEqualSlices(u32, &expected, &result);
}
