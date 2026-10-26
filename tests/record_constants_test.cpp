// -----------------------------------------------------------------------------
// record_constants_test.cpp
//
// Unit tests for the TLS 1.3 record-layer layout constants (RFC 8446 §5.1,
// §5.2). These define the exact bytes that surround every encrypted record on
// the wire, so getting them wrong means records that are unparseable by any
// peer. They also define the AAD (Additional Authenticated Data) size, which
// is central to the tamper-resistance property we will test later.
//
// C++ note: these are inline constexpr variables (C++17). In C++11 you would
// have needed either (a) static constexpr class members with a separate
// out-of-line definition in one TU, or (b) enum constants. inline constexpr
// gives us a single, typed, namespaced definition shared by all translation
// units with zero ODR (One Definition Rule) headaches.
// -----------------------------------------------------------------------------

#include <gtest/gtest.h>

#include <cstddef>
#include <cstdint>

#include "mtls_core/record_constants.hpp"

using namespace mtls_core;

// --- Positive: record header geometry -------------------------------------
//
// A TLS 1.3 "TLSCiphertext" record header is exactly 5 bytes:
//     opaque_type (1) + legacy_record_version (2) + length (2)
// The header is NOT encrypted, but it IS authenticated (it is the AAD), so its
// exact size feeds directly into the AEAD call.

TEST(RecordConstantsTest, RecordHeaderLengthIsFiveBytes) {
    EXPECT_EQ(kRecordHeaderLength, std::size_t{5});
}

// --- Positive: content-type bytes -----------------------------------------
//
// These single-byte values identify the record type. TLS 1.3 only ever puts
// the "real" type inside the encrypted payload; the outer type is normally
// application_data (23) to hide the true type from passive observers.

TEST(RecordConstantsTest, ContentTypeBytesMatchRegistry) {
    EXPECT_EQ(kContentTypeChangeCipherSpec, std::uint8_t{20});
    EXPECT_EQ(kContentTypeAlert, std::uint8_t{21});
    EXPECT_EQ(kContentTypeHandshake, std::uint8_t{22});
    EXPECT_EQ(kContentTypeApplicationData, std::uint8_t{23});
}

// --- Positive: legacy version ---------------------------------------------
//
// TLS 1.3 deliberately sets legacy_record_version to 0x0303 (the TLS 1.2
// value) for backwards compatibility with middleboxes. The actual protocol
// version is negotiated in the supported_versions extension, not here.

TEST(RecordConstantsTest, LegacyRecordVersionIsTls12WireValue) {
    EXPECT_EQ(kLegacyRecordVersion, std::uint16_t{0x0303});
}

// --- Boundary: maximum record sizes ---------------------------------------
//
// RFC 8446 §5.2:
//   * Maximum plaintext  in a TLSCiphertext record is 2^14 = 16384 bytes.
//   * Maximum ciphertext is 2^14 + 256 = 16640 bytes (room for tag + expansion).
// These bounds drive the length fields in the header and prevent buffer
// overflows in the record layer we will build next.

TEST(RecordConstantsTest, MaxPlaintextRecordLengthIsTwoToTheFourteen) {
    EXPECT_EQ(kMaxPlaintextRecordLength, std::size_t{16384});  // 2^14
}

TEST(RecordConstantsTest, MaxCiphertextRecordLengthIsTwoToTheFourteenPlus256) {
    EXPECT_EQ(kMaxCiphertextRecordLength, std::size_t{16640});  // 2^14 + 256
}

// --- Positive: AAD size ----------------------------------------------------
//
// The AEAD AAD for a TLS 1.3 record is exactly the 5-byte record header. The
// length field inside that header is set to the ciphertext length so that an
// attacker cannot truncate or extend a record without invalidating the tag.

TEST(RecordConstantsTest, AdditionalDataLengthEqualsHeaderLength) {
    EXPECT_EQ(kAdditionalDataLength, kRecordHeaderLength);
    EXPECT_EQ(kAdditionalDataLength, std::size_t{5});
}
