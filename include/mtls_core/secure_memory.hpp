// -----------------------------------------------------------------------------
// mtls_core/secure_memory.hpp
//
// Memory primitives for handling *secrets* (keys, IVs, plaintext).
//
// A plain std::vector<std::uint8_t> or a raw `new[]`/`delete[]` pair is not
// good enough for secrets, for two reasons:
//
//   1. When the memory is freed, the bytes are NOT erased — they remain in RAM
//      until something else overwrites them. A key that "went out of scope"
//      can still be read from a later heap allocation, a core dump, or swap.
//
//   2. Even if you remember to erase, a naive `memset(p, 0, n)` is a *dead
//      store*: if the compiler proves the buffer is never read again, it is
//      allowed to delete the erase entirely. (This is a documented, real-world
//      bug class.)
//
// This header provides:
//   * secure_scrub(ptr, n) — zeroize that the compiler cannot optimize away,
//     backed by OpenSSL's OPENSSL_cleanse.
//   * SecureBuffer          — a move-only, RAII byte buffer that scrubs itself
//     on destruction and on resize.
// -----------------------------------------------------------------------------

#pragma once

#include <cstddef>   // std::size_t
#include <cstdint>   // std::uint8_t
#include <span>      // std::span (C++20)

namespace mtls_core {

// -----------------------------------------------------------------------------
// secure_scrub
// -----------------------------------------------------------------------------
// Overwrites `n` bytes starting at `ptr` with zeros in a way the compiler is
// not allowed to eliminate. Safe to call with `ptr == nullptr` and/or `n == 0`
// (both are no-ops).
//
// The implementation delegates to OPENSSL_cleanse (see secure_memory.cpp for
// why that, and not plain memset, is correct). We keep OpenSSL out of this
// public header so consumers of the library do not need to know about it.

void secure_scrub(void* ptr, std::size_t n) noexcept;

// -----------------------------------------------------------------------------
// SecureBuffer
// -----------------------------------------------------------------------------
// A move-only, fixed-once-sized buffer of bytes that guarantees its contents
// are scrubbed (zeroized) when the buffer is destroyed or resized.
//
// Design decisions, and the C++ reasoning behind each:
//
//   * Move-only (copy ctor/assign = delete). Copying a secret duplicates it:
//     now there are two places that must be scrubbed, and the copy may outlive
//     the original's erase. Like std::unique_ptr, we model *unique ownership*
//     of an un-copyable resource.
//
//   * noexcept move. A moved-from SecureBuffer is emptied (size 0, data null).
//     noexcept lets standard containers relocate us without copying, and keeps
//     the move path non-throwing — important because a throwing move could
//     leave a half-transferred secret.
//
//   * std::span views. span() returns a non-owning view {pointer, length} of
//     the buffer. In C++11 you would pass (T* ptr, size_t len) as two separate
//     arguments — easy to get out of sync. std::span carries both, enables
//     range-for and <algorithm>, and gives bounds-checked operator[] in debug.
//
//   * std::uint8_t (not char). Crypto APIs and OpenSSL operate on raw octets.
//     std::uint8_t is exactly 8 bits (where plain `char` is signedness- and
//     width- platform-dependent), and it is the type OpenSSL's EVP layer uses
//     (unsigned char*). (C++17's std::byte is an alternative with stricter
//     "raw storage" semantics, but std::uint8_t interops with OpenSSL directly.)

class SecureBuffer {
public:
    using value_type = std::uint8_t;
    using size_type  = std::size_t;

    // Constructs a buffer of `size` bytes, all zero-initialized. A size of 0
    // yields an empty buffer (data() == nullptr).
    explicit SecureBuffer(size_type size = 0);

    // Scrubs the contents, then releases the memory.
    ~SecureBuffer();

    // Copying is forbidden (see class comment).
    SecureBuffer(const SecureBuffer&) = delete;
    SecureBuffer& operator=(const SecureBuffer&) = delete;

    // Move transfers ownership and empties the source.
    SecureBuffer(SecureBuffer&& other) noexcept;
    SecureBuffer& operator=(SecureBuffer&& other) noexcept;

    // Raw access. Unchecked, like std::vector::operator[].
    value_type*       data() noexcept { return data_; }
    const value_type* data() const noexcept { return data_; }

    size_type size() const noexcept { return size_; }
    bool      empty() const noexcept { return size_ == 0; }

    // Non-owning view of the same bytes (C++20 std::span).
    std::span<value_type>       span() noexcept { return {data_, size_}; }
    std::span<const value_type> span() const noexcept { return {data_, size_}; }

    value_type&       operator[](size_type i) noexcept { return data_[i]; }
    const value_type& operator[](size_type i) const noexcept { return data_[i]; }

    // Zeroizes the contents in place (does NOT release memory).
    void scrub() noexcept;

    // Changes the size, scrubbing any discarded bytes. Strong exception
    // guarantee: if allocation fails, the original buffer is left untouched.
    void resize(size_type new_size);

private:
    value_type* data_ = nullptr;
    size_type   size_ = 0;
};

}  // namespace mtls_core
