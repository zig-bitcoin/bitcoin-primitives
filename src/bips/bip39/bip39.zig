//! # BIP39 Mnemonic Codes
//!
//! https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki
//!
const std = @import("std");
const language = @import("language.zig");
const pbkdf2 = @import("pbkdf2.zig");

/// The minimum number of words in a mnemonic.
const MIN_NB_WORDS: usize = 12;

/// The maximum number of words in a mnemonic.
const MAX_NB_WORDS: usize = 24;

/// The index used to indicate the mnemonic ended.
const EOF: u16 = std.math.maxInt(u16);

/// A mnemonic code.
///
/// The [core::str::FromStr] implementation will try to determine the language of the
/// mnemonic from all the supported languages. (Languages have to be explicitly enabled using
/// the Cargo features.)
///
/// Supported number of words are 12, 15, 18, 21, and 24.
pub const Mnemonic = struct {
    /// The language the mnemonic.
    lang: language.Language,
    /// The indiced of the words.
    /// Mnemonics with less than the max nb of words are terminated with EOF.
    words: [MAX_NB_WORDS]u16,

    /// Parse a mnemonic in normalized UTF8 in the given language.
    pub fn parseInNormalized(lang: language.Language, s: []const u8) !Mnemonic {
        var it = std.mem.splitScalar(u8, s, ' ');
        var nb_words: usize = 0;

        while (it.next()) |_| nb_words += 1;
        it.reset();

        if (isInvalidWordCount(nb_words)) {
            return error.BadWordCount;
        }

        // Here we will store the eventual words.
        var words = [_]u16{EOF} ** MAX_NB_WORDS;

        // And here we keep track of the bits to calculate and validate the checksum.
        // We only use `nb_words * 11` elements in this array.
        var bits = [_]bool{false} ** (MAX_NB_WORDS * 11);

        {
            var i: usize = 0;
            while (it.next()) |word| {
                const idx = lang.findWord(word) orelse return error.UnknownWord;

                words[i] = idx;

                for (0..11) |j| {
                    bits[i * 11 + j] = std.math.shr(u16, idx, 10 - j) & 1 == 1;
                }
                i += 1;
            }
        }

        // Verify the checksum.
        // We only use `nb_words / 3 * 4` elements in this array.

        var entropy = [_]u8{0} ** (MAX_NB_WORDS / 3 * 4);
        const nb_bytes_entropy = nb_words / 3 * 4;
        for (0..nb_bytes_entropy) |i| {
            for (0..8) |j| {
                if (bits[i * 8 + j]) {
                    entropy[i] += std.math.shl(u8, 1, 7 - j);
                }
            }
        }

        var hasher = std.crypto.hash.sha2.Sha256.init(.{});
        hasher.update(entropy[0..nb_bytes_entropy]);

        const check = hasher.finalResult();

        for (0..nb_bytes_entropy / 4) |i| {
            if (bits[8 * nb_bytes_entropy + i] != ((check[i / 8] & (std.math.shl(usize, 1, 7 - (i % 8)))) > 0)) {
                return error.InvalidChecksum;
            }
        }

        return .{
            .lang = lang,
            .words = words,
        };
    }

    /// Convert to seed bytes with a passphrase in normalized UTF8.
    pub fn toSeedNormalized(self: Mnemonic, normalized_passphrase: []const u8) ![64]u8 {
        const PBKDF2_ROUNDS: usize = 2048;
        const PBKDF2_BYTES: usize = 64;

        var seed = [_]u8{0} ** PBKDF2_BYTES;

        pbkdf2.pbkdf2((try self.getWords()).slice(), normalized_passphrase, PBKDF2_ROUNDS, &seed);
        return seed;
    }

    /// Returns an slice over [Mnemonic] word indices.
    ///
    pub fn wordIndices(self: Mnemonic) !std.BoundedArray(u16, MAX_NB_WORDS) {
        var result = try std.BoundedArray(u16, MAX_NB_WORDS).init(0);

        for (self.words) |w| {
            if (w != EOF) {
                result.appendAssumeCapacity(w);
                continue;
            }

            break;
        }

        return result;
    }

    /// Returns an iterator over the words of the [Mnemonic].
    ///
    /// # Examples
    ///
    /// Basic usage:
    ///
    /// ```
    /// const bip39 = @import("bip39");
    ///
    /// const mnemonic = try bip39.Mnemonic.fromEntropy(&([_]u8{0} ** 32));
    /// for (mnemonic.words()) |word| {
    ///     std.log.debug("word: {s}", .{word});
    /// }
    /// ```
    pub fn getWords(self: Mnemonic) !std.BoundedArray([]const u8, MAX_NB_WORDS) {
        const list = self.lang.wordList();
        const word_indices = try self.wordIndices();

        var result = try std.BoundedArray([]const u8, MAX_NB_WORDS).init(0);

        for (word_indices.slice()) |i| {
            result.appendAssumeCapacity(list[i]);
        }

        return result;
    }

    /// Create a new [Mnemonic] in the specified language from the given entropy.
    /// Entropy must be a multiple of 32 bits (4 bytes) and 128-256 bits in length.
    pub fn fromEntropyIn(lang: language.Language, entropy: []const u8) !Mnemonic {
        const MAX_ENTROPY_BITS: usize = 256;
        const MIN_ENTROPY_BITS: usize = 128;
        const MAX_CHECKSUM_BITS: usize = 8;

        const nb_bytes = entropy.len;
        const nb_bits = nb_bytes * 8;

        if (nb_bits % 32 != 0) {
            return error.BadEntropyBitCount;
        }

        if (nb_bits < MIN_ENTROPY_BITS or nb_bits > MAX_ENTROPY_BITS) {
            return error.BadEntropyBitCount;
        }

        const check = v: {
            var out: [std.crypto.hash.sha2.Sha256.digest_length]u8 = undefined;
            std.crypto.hash.sha2.Sha256.hash(entropy, &out, .{});
            break :v out;
        };

        var bits = [_]bool{false} ** (MAX_ENTROPY_BITS + MAX_CHECKSUM_BITS);

        for (0..nb_bytes) |i| {
            for (0..8) |j| {
                bits[i * 8 + j] = (entropy[i] & (std.math.shl(usize, 1, 7 - j))) > 0;
            }
        }

        for (0..nb_bytes / 4) |i| {
            bits[8 * nb_bytes + i] = (check[i / 8] & (std.math.shl(usize, 1, 7 - (i % 8)))) > 0;
        }

        var words = [_]u16{EOF} ** MAX_NB_WORDS;
        const nb_words = nb_bytes * 3 / 4;
        for (0..nb_words) |i| {
            var idx: u16 = 0;
            for (0..11) |j| {
                if (bits[i * 11 + j]) {
                    idx += std.math.shl(u16, 1, @as(u16, @truncate(10 - j)));
                }
            }

            words[i] = idx;
        }

        return .{
            .lang = lang,
            .words = words,
        };
    }
};

fn isInvalidWordCount(word_count: usize) bool {
    return word_count < MIN_NB_WORDS or word_count % 3 != 0 or word_count > MAX_NB_WORDS;
}

test "english_vectors" {
    // These vectors are tuples of
    // (entropy, mnemonic, seed)

    const test_vectors = [_]struct { []const u8, []const u8, []const u8 }{
        .{
            "00000000000000000000000000000000",
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
            "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04",
        },
        .{
            "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
            "legal winner thank year wave sausage worth useful legal winner thank yellow",
            "2e8905819b8723fe2c1d161860e5ee1830318dbf49a83bd451cfb8440c28bd6fa457fe1296106559a3c80937a1c1069be3a3a5bd381ee6260e8d9739fce1f607",
        },
        .{
            "80808080808080808080808080808080",
            "letter advice cage absurd amount doctor acoustic avoid letter advice cage above",
            "d71de856f81a8acc65e6fc851a38d4d7ec216fd0796d0a6827a3ad6ed5511a30fa280f12eb2e47ed2ac03b5c462a0358d18d69fe4f985ec81778c1b370b652a8",
        },
        .{
            "ffffffffffffffffffffffffffffffff",
            "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong",
            "ac27495480225222079d7be181583751e86f571027b0497b5b5d11218e0a8a13332572917f0f8e5a589620c6f15b11c61dee327651a14c34e18231052e48c069",
        },
        .{
            "000000000000000000000000000000000000000000000000",
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon agent",
            "035895f2f481b1b0f01fcf8c289c794660b289981a78f8106447707fdd9666ca06da5a9a565181599b79f53b844d8a71dd9f439c52a3d7b3e8a79c906ac845fa",
        },
        .{
            "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
            "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal will",
            "f2b94508732bcbacbcc020faefecfc89feafa6649a5491b8c952cede496c214a0c7b3c392d168748f2d4a612bada0753b52a1c7ac53c1e93abd5c6320b9e95dd",
        },
        .{
            "808080808080808080808080808080808080808080808080",
            "letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter always",
            "107d7c02a5aa6f38c58083ff74f04c607c2d2c0ecc55501dadd72d025b751bc27fe913ffb796f841c49b1d33b610cf0e91d3aa239027f5e99fe4ce9e5088cd65",
        },
        .{
            "ffffffffffffffffffffffffffffffffffffffffffffffff",
            "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo when",
            "0cd6e5d827bb62eb8fc1e262254223817fd068a74b5b449cc2f667c3f1f985a76379b43348d952e2265b4cd129090758b3e3c2c49103b5051aac2eaeb890a528",
        },
        .{
            "0000000000000000000000000000000000000000000000000000000000000000",
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art",
            "bda85446c68413707090a52022edd26a1c9462295029f2e60cd7c4f2bbd3097170af7a4d73245cafa9c3cca8d561a7c3de6f5d4a10be8ed2a5e608d68f92fcc8",
        },
        .{
            "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
            "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth title",
            "bc09fca1804f7e69da93c2f2028eb238c227f2e9dda30cd63699232578480a4021b146ad717fbb7e451ce9eb835f43620bf5c514db0f8add49f5d121449d3e87",
        },
        .{
            "8080808080808080808080808080808080808080808080808080808080808080",
            "letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic bless",
            "c0c519bd0e91a2ed54357d9d1ebef6f5af218a153624cf4f2da911a0ed8f7a09e2ef61af0aca007096df430022f7a2b6fb91661a9589097069720d015e4e982f",
        },
        .{
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo vote",
            "dd48c104698c30cfe2b6142103248622fb7bb0ff692eebb00089b32d22484e1613912f0a5b694407be899ffd31ed3992c456cdf60f5d4564b8ba3f05a69890ad",
        },
        .{
            "9e885d952ad362caeb4efe34a8e91bd2",
            "ozone drill grab fiber curtain grace pudding thank cruise elder eight picnic",
            "274ddc525802f7c828d8ef7ddbcdc5304e87ac3535913611fbbfa986d0c9e5476c91689f9c8a54fd55bd38606aa6a8595ad213d4c9c9f9aca3fb217069a41028",
        },
        .{
            "6610b25967cdcca9d59875f5cb50b0ea75433311869e930b",
            "gravity machine north sort system female filter attitude volume fold club stay feature office ecology stable narrow fog",
            "628c3827a8823298ee685db84f55caa34b5cc195a778e52d45f59bcf75aba68e4d7590e101dc414bc1bbd5737666fbbef35d1f1903953b66624f910feef245ac",
        },
        .{
            "68a79eaca2324873eacc50cb9c6eca8cc68ea5d936f98787c60c7ebc74e6ce7c",
            "hamster diagram private dutch cause delay private meat slide toddler razor book happy fancy gospel tennis maple dilemma loan word shrug inflict delay length",
            "64c87cde7e12ecf6704ab95bb1408bef047c22db4cc7491c4271d170a1b213d20b385bc1588d9c7b38f1b39d415665b8a9030c9ec653d75e65f847d8fc1fc440",
        },
        .{
            "c0ba5a8e914111210f2bd131f3d5e08d",
            "scheme spot photo card baby mountain device kick cradle pact join borrow",
            "ea725895aaae8d4c1cf682c1bfd2d358d52ed9f0f0591131b559e2724bb234fca05aa9c02c57407e04ee9dc3b454aa63fbff483a8b11de949624b9f1831a9612",
        },
        .{
            "6d9be1ee6ebd27a258115aad99b7317b9c8d28b6d76431c3",
            "horn tenant knee talent sponsor spell gate clip pulse soap slush warm silver nephew swap uncle crack brave",
            "fd579828af3da1d32544ce4db5c73d53fc8acc4ddb1e3b251a31179cdb71e853c56d2fcb11aed39898ce6c34b10b5382772db8796e52837b54468aeb312cfc3d",
        },
        .{
            "9f6a2878b2520799a44ef18bc7df394e7061a224d2c33cd015b157d746869863",
            "panda eyebrow bullet gorilla call smoke muffin taste mesh discover soft ostrich alcohol speed nation flash devote level hobby quick inner drive ghost inside",
            "72be8e052fc4919d2adf28d5306b5474b0069df35b02303de8c1729c9538dbb6fc2d731d5f832193cd9fb6aeecbc469594a70e3dd50811b5067f3b88b28c3e8d",
        },
        .{
            "23db8160a31d3e0dca3688ed941adbf3",
            "cat swing flag economy stadium alone churn speed unique patch report train",
            "deb5f45449e615feff5640f2e49f933ff51895de3b4381832b3139941c57b59205a42480c52175b6efcffaa58a2503887c1e8b363a707256bdd2b587b46541f5",
        },
        .{
            "8197a4a47f0425faeaa69deebc05ca29c0a5b5cc76ceacc0",
            "light rule cinnamon wrap drastic word pride squirrel upgrade then income fatal apart sustain crack supply proud access",
            "4cbdff1ca2db800fd61cae72a57475fdc6bab03e441fd63f96dabd1f183ef5b782925f00105f318309a7e9c3ea6967c7801e46c8a58082674c860a37b93eda02",
        },
        .{
            "066dca1a2bb7e8a1db2832148ce9933eea0f3ac9548d793112d9a95c9407efad",
            "all hour make first leader extend hole alien behind guard gospel lava path output census museum junior mass reopen famous sing advance salt reform",
            "26e975ec644423f4a4c4f4215ef09b4bd7ef924e85d1d17c4cf3f136c2863cf6df0a475045652c57eb5fb41513ca2a2d67722b77e954b4b3fc11f7590449191d",
        },
        .{
            "f30f8c1da665478f49b001d94c5fc452",
            "vessel ladder alter error federal sibling chat ability sun glass valve picture",
            "2aaa9242daafcee6aa9d7269f17d4efe271e1b9a529178d7dc139cd18747090bf9d60295d0ce74309a78852a9caadf0af48aae1c6253839624076224374bc63f",
        },
        .{
            "c10ec20dc3cd9f652c7fac2f1230f7a3c828389a14392f05",
            "scissors invite lock maple supreme raw rapid void congress muscle digital elegant little brisk hair mango congress clump",
            "7b4a10be9d98e6cba265566db7f136718e1398c71cb581e1b2f464cac1ceedf4f3e274dc270003c670ad8d02c4558b2f8e39edea2775c9e232c7cb798b069e88",
        },
        .{
            "f585c11aec520db57dd353c69554b21a89b20fb0650966fa0a9d6f74fd989d8f",
            "void come effort suffer camp survey warrior heavy shoot primary clutch crush open amazing screen patrol group space point ten exist slush involve unfold",
            "01f5bced59dec48e362f2c45b5de68b9fd6c92c6634f44d6d40aab69056506f0e35524a518034ddc1192e1dacd32c1ed3eaa3c3b131c88ed8e7e54c49a5d0998",
        },
    };

    var buf: [300]u8 = undefined;

    for (test_vectors) |vector| {
        const entropy = try std.fmt.hexToBytes(&buf, vector[0]);
        const mn = try Mnemonic.fromEntropyIn(.english, entropy);
        const mn1 = try Mnemonic.parseInNormalized(.english, vector[1]);

        try std.testing.expectEqualDeep(mn, mn1);

        const seed = try std.fmt.hexToBytes(buf[100..], vector[2]);

        const seeded = try mn.toSeedNormalized("TREZOR");

        try std.testing.expectEqualSlices(u8, &seeded, seed);
    }
}
