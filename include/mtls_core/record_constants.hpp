// -----------------------------------------------------------------------------
// mtls_core/record_constants.hpp
//
// TLS 1.3 record-layer layout constants (RFC 8446 §5.1 and §5.2). These are
// the fixed numbers that govern the bytes surrounding every encrypted record:
// the record header, the content-type values, and the maximum record sizes.
// -----------------------------------------------------------------------------

#pragma once

#include <cstddef>   // std::size_t
#include <cstdint>   // std::uint8_t, std::uint16_t

namespace mtls_core {

// ---------------------------------------------------------------------------
// Record header size
// ---------------------------------------------------------------------------
// A TLS 1.3 TLSCiphertext record header is exactly 5 bytes:
//
//     struct {
//         ContentType        opaque_type;        // 1 byte
//         ProtocolVersion    legacy_record_version;  // 2 bytes (0x0303)
//         uint16             length;             // 2 bytes (ciphertext len)
//     } TLSCiphertext;
//
// The header is sent in the clear but is authenticated as AAD, so an attacker
// cannot alter the content type or the length without breaking the tag.

inline constexpr std::size_t kRecordHeaderLength = 5;

// ---------------------------------------------------------------------------
// Content types
// ---------------------------------------------------------------------------
// One-byte values identifying a record's purpose. TLS 1.3 puts the real type
// inside the encrypted payload; the outer opaque_type is normally
// application_data (23) to hide the true type from passive observers.

inline constexpr std::uint8_t kContentTypeChangeCipherSpec = 20;  // 0x14
inline constexpr std::uint8_t kContentTypeAlert = 21;             // 0x15
inline constexpr std::uint8_t kContentTypeHandshake = 22;         // 0x16
inline constexpr std::uint8_t kContentTypeApplicationData = 23;   // 0x17

// ---------------------------------------------------------------------------
// Legacy record version
// ---------------------------------------------------------------------------
// TLS 1.3 writes 0x0303 (the TLS 1.2 wire version) into legacy_record_version
// for compatibility with middleboxes that inspect this field. The real version
// is negotiated in the supported_versions extension.

inline constexpr std::uint16_t kLegacyRecordVersion = 0x0303;

// ---------------------------------------------------------------------------
// Maximum record sizes (RFC 8446 §5.2)
// ---------------------------------------------------------------------------
//   * kMaxPlaintextRecordLength  = 2^14        = 16384 bytes.
//   * kMaxCiphertextRecordLength = 2^14 + 256  = 16640 bytes (header+tag room).
//
// The +256 upper bound accounts for the maximum AEAD expansion (tag + any
// padding). The 2-byte length field can represent up to 65535, so 16640 fits
// comfortably; the tighter bound exists to keep memory usage bounded.

inline constexpr std::size_t kMaxPlaintextRecordLength = 1u << 14;          // 16384
inline constexpr std::size_t kMaxCiphertextRecordLength = (1u << 14) + 256; // 16640

// ---------------------------------------------------------------------------
// AAD length
// ---------------------------------------------------------------------------
// The AEAD Additional Authenticated Data for a TLS 1.3 record is exactly the
// 5-byte record header (RFC 8446 §5.2). AAD is authenticated but not
// encrypted: it binds the ciphertext to the (content type, version, length)
// header so that truncation, extension, or type-spoofing is detected.

inline constexpr std::size_t kAdditionalDataLength = kRecordHeaderLength;  // 5

}  // namespace mtls_core
