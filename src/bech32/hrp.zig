const std = @import("std");
const expect = std.testing.expect;
const expectEqualSlices = std.testing.expectEqualSlices;
const expectError = std.testing.expectError;

/// The human readable part of a bech32 address is limited to 83 US-ASCII characters.
const MAX_HRP_LEN: usize = 83;

/// The minimum ASCII value for a valid character in the human readable part.
const MIN_ASCII: u8 = 33;

/// The maximum ASCII value for a valid character in the human readable part.
const MAX_ASCII: u8 = 126;

/// Various errors that can occur during HRP processing.
///
/// These errors help in validating and debugging issues with bech32 address formatting.
const HrpError = error{
    /// This error occurs when the provided human-readable part (HRP) is empty.
    ///
    /// A valid HRP must contain at least one character to comply with the
    /// specification, and this error signals the absence of such a character.
    EmptyHrp,

    /// This error is returned when the HRP exceeds the maximum allowed length.
    ///
    /// According to the specification, the HRP must not exceed 83 characters.
    /// This error occurs if the HRP length is greater than the allowed limit.
    TooLongHrp,

    /// This error occurs when a non-ASCII character is found in the HRP.
    ///
    /// The HRP is restricted to US-ASCII characters (values between 33 and 126).
    /// This error indicates that a character outside of this range was encountered.
    NonAsciiChar,

    /// This error is returned when the HRP contains a character that falls
    /// outside the valid ASCII range for a bech32-encoded string.
    ///
    /// The HRP should only contain characters within the range of 33 to 126.
    /// If a character falls outside of this range, this error is triggered.
    InvalidAsciiByte,

    /// This error occurs when the HRP contains both uppercase and lowercase letters.
    ///
    /// To ensure consistency and compatibility, the HRP must either be fully
    /// lowercase or fully uppercase. Mixing of cases is not allowed, and this
    /// error indicates a violation of that rule.
    MixedCaseHrp,
};

/// Represents the human-readable part (HRP) of a Bech32 encoded string.
///
/// The HRP is the prefix of a Bech32 string that is used to convey contextual information about the
/// encoded data (such as the blockchain network or address type).
///
/// The Bech32 specification, defined in [BIP-173](https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki),
/// restricts the HRP to 1-83 characters from the US-ASCII set, with the characters required to be in the range
/// of ASCII values 33-126.
/// Furthermore, HRP must not be mixed-case (i.e., it cannot contain both uppercase and lowercase letters).
pub const Hrp = struct {
    const Self = @This();

    /// ASCII buffer for the human readable part.
    ///
    /// This buffer stores the validated HRP string characters and is initialized to zeros.
    /// The size of the buffer is fixed at `MAX_HRP_LEN` (83 bytes) to match the Bech32 specification.
    ///
    /// # Guarantee:
    /// The buffer ensures that no mixed-case characters are stored in the HRP (all characters will either be lowercase
    /// or uppercase, but not both).
    buf: [MAX_HRP_LEN]u8 = [_]u8{0} ** MAX_HRP_LEN,
    /// The number of characters currently stored in the HRP.
    ///
    /// This value tracks how many bytes from the buffer are actively used for the HRP. It will always be
    /// less than or equal to `MAX_HRP_LEN`.
    size: usize = 0,

    /// Parses and validates a human-readable part (HRP) according to the Bech32 specification.
    ///
    /// This function checks that the provided `hrp` string is valid according to the Bech32 rules as defined in
    /// BIP-173. The HRP must:
    ///
    /// - Be between 1 and 83 characters in length.
    /// - Contain only valid US-ASCII characters within the range [33-126].
    /// - Not be mixed-case, meaning it must either be all lowercase or all uppercase, but not both.
    ///
    /// # Parameters:
    /// - `hrp`: A byte slice representing the HRP string to validate.
    ///
    /// # Returns:
    /// - Returns an `Hrp` struct if the HRP is valid.
    /// - Returns an error if the HRP is empty, too long, contains invalid characters, or is mixed-case.
    pub fn parse(hrp: []const u8) HrpError!Self {
        // Check if the provided HRP is empty, as an HRP must contain at least one character.
        if (hrp.len == 0)
            return HrpError.EmptyHrp;

        // Check if the HRP exceeds the maximum allowed length of 83 characters, returning an error if it does.
        if (hrp.len > MAX_HRP_LEN)
            return HrpError.TooLongHrp;

        // Create a new instance of the `Hrp` struct, initializing the buffer with zeros and size with 0.
        var new = Self{};

        // Flags to detect if there are any lowercase or uppercase letters in the HRP.
        var has_lower = false;
        var has_upper = false;

        // Loop through each character of the HRP by its index `i` and character `c`.
        for (hrp, 0..) |c, i| {

            // Check if the current character is a valid ASCII character (0-127).
            if (!std.ascii.isAscii(c))
                return HrpError.NonAsciiChar;

            // Ensure that the character is within the valid range of ASCII values for Bech32 (33-126).
            // Characters outside this range are invalid.
            if (c < MIN_ASCII or c > MAX_ASCII)
                return HrpError.InvalidAsciiByte;

            // If the character is lowercase, ensure that no uppercase characters have been encountered so far.
            // If an uppercase character was already found, return a `MixedCaseHrp` error.
            if (std.ascii.isLower(c)) {
                if (has_upper)
                    return HrpError.MixedCaseHrp;

                // Mark that a lowercase letter has been found.
                has_lower = true;
            } else if (std.ascii.isUpper(c)) {
                // If the character is uppercase, ensure that no lowercase characters have been encountered.
                // If a lowercase character was already found, return a `MixedCaseHrp` error.
                if (has_lower)
                    return HrpError.MixedCaseHrp;

                // Mark that an uppercase letter has been found.
                has_upper = true;
            }

            // Store the valid character into the buffer at the current index.
            new.buf[i] = c;
            // Increment the size of the HRP by 1 to account for the newly added character.
            new.size += 1;
        }

        // Return the constructed and validated `Hrp` instance.
        return new;
    }
};

test "Hrp: check parse is ok" {
    // Some valid human readable parts.
    //
    // Taken from https://github.com/rust-bitcoin/rust-bech32/blob/master/src/primitives/hrp.rs
    const cases = [_][]const u8{
        "a",
        "A",
        "abcdefg",
        "ABCDEFG",
        "abc123def",
        "ABC123DEF",
        "!\"#$%&'()*+,-./",
        "1234567890",
    };

    // Go through all the test cases.
    for (cases) |c| {
        // Check that the human readable part is parsed correctly.
        const hrp = try Hrp.parse(c);
        // Check that the human readable part is correctly stored in the buffer.
        try expectEqualSlices(u8, c, hrp.buf[0..hrp.size]);
        // Check that the remaining buffer is zeroed.
        for (hrp.buf[hrp.size..]) |b| try expect(b == 0);
        // Check that the size is correct.
        try expect(hrp.size == c.len);
    }
}

test "Hrp: mixed case Hrp should fail parsing" {
    // A human readable part that contains both uppercase and lowercase characters.
    const case = "has-capitals-aAbB";
    // Attempt to parse the mixed-case HRP, expecting a `MixedCaseHrp` error.
    try expectError(HrpError.MixedCaseHrp, Hrp.parse(case));
}

test "Hrp: empty Hrp should fail parsing" {
    // An empty human readable part.
    const case = "";
    // Attempt to parse the empty HRP, expecting an `EmptyHrp` error.
    try expectError(HrpError.EmptyHrp, Hrp.parse(case));
}

test "Hrp: Hrp with non ASCII character should fail parsing" {
    // A human readable part that contains invalid ASCII characters.
    const case = "has-value-out-of-range-∈∈∈∈∈∈∈∈";
    // Attempt to parse the HRP with invalid characters, expecting an `InvalidAsciiByte` error.
    try expectError(HrpError.NonAsciiChar, Hrp.parse(case));
}

test "Hrp: Hrp with too many characters should fail parsing" {
    // A human readable part that exceeds the maximum allowed length.
    const case = "toolongtoolongtoolongtoolongtoolongtoolongtoolongtoolongtoolongtoolongtoolongtoolongtoolongtoolong";
    // Attempt to parse the HRP that is too long, expecting a `TooLongHrp` error.
    try expectError(HrpError.TooLongHrp, Hrp.parse(case));
}

test "Hrp: Hrp with invalid ASCII byte should fail parsing" {
    // A human readable part that contains invalid ASCII characters.
    const case = "has spaces in it";
    // Attempt to parse the HRP with invalid characters, expecting an `InvalidAsciiByte` error.
    try expectError(HrpError.InvalidAsciiByte, Hrp.parse(case));
}
