// -----------------------------------------------------------------------------
// secure_memory.cpp
//
// Implementation of secure_scrub() and SecureBuffer.
// -----------------------------------------------------------------------------

#include "mtls_core/secure_memory.hpp"

#include <openssl/crypto.h>  // OPENSSL_cleanse

#include <algorithm>  // std::copy, std::min

namespace mtls_core {

// -----------------------------------------------------------------------------
// secure_scrub
// -----------------------------------------------------------------------------
// We delegate to OPENSSL_cleanse rather than calling memset ourselves.
//
// WHY NOT JUST `memset(ptr, 0, n)`?
//   A C++ (or C) compiler is allowed to observe that a write to memory that is
//   never subsequently *read* has no effect on the program's observable
//   behaviour, and delete it as a "dead store". If you memset a key buffer
//   right before freeing it, an optimizing compiler may conclude "nobody reads
//   this again" and remove the memset — silently leaving your key in freed
//   memory. This is not a theoretical concern; it is a documented bug class
//   that has bitten real crypto libraries.
//
//   OPENSSL_cleanse defeats the optimizer. Historically it did this by calling
//   memset through a `volatile` function pointer: because the compiler cannot
//   prove what a function called through a volatile pointer does, it must
//   assume the call has side effects and cannot elide it. Modern versions may
//   use inline assembly or platform intrinsics (explicit_bzero / memset_s) for
//   the same guarantee.
//
//   Because we already link OpenSSL for the AEAD, OPENSSL_cleanse gives us the
//   battle-tested, portable primitive for free on every platform we target.

void secure_scrub(void* ptr, std::size_t n) noexcept {
    if (ptr == nullptr || n == 0) {
        return;  // defensive: OPENSSL_cleanse is also safe here, but be explicit
    }
    OPENSSL_cleanse(ptr, n);
}

// -----------------------------------------------------------------------------
// SecureBuffer
// -----------------------------------------------------------------------------

SecureBuffer::SecureBuffer(size_type size) : size_(size) {
    if (size_ == 0) {
        data_ = nullptr;  // empty buffer: a valid state (e.g. an empty record)
        return;
    }
    // `new value_type[n]` default-initializes the elements, which for a
    // fundamental type leaves them *indeterminate* (garbage). We immediately
    // scrub-to-zero so a fresh buffer is deterministic and never leaks a prior
    // allocation's leftover bytes.
    data_ = new value_type[size_];  // may throw std::bad_alloc
    secure_scrub(data_, size_);
}

SecureBuffer::~SecureBuffer() {
    if (data_ != nullptr) {
        secure_scrub(data_, size_);  // erase the secret BEFORE releasing memory
        delete[] data_;
    }
}

SecureBuffer::SecureBuffer(SecureBuffer&& other) noexcept
    : data_(other.data_), size_(other.size_) {
    other.data_ = nullptr;  // transfer ownership; empty the source
    other.size_ = 0;
}

SecureBuffer& SecureBuffer::operator=(SecureBuffer&& other) noexcept {
    if (this != &other) {
        // Scrub our OLD secret before we overwrite our pointer to it, so the
        // old bytes are not leaked when they are eventually freed.
        if (data_ != nullptr) {
            secure_scrub(data_, size_);
            delete[] data_;
        }
        data_ = other.data_;
        size_ = other.size_;
        other.data_ = nullptr;
        other.size_ = 0;
    }
    return *this;
}

void SecureBuffer::scrub() noexcept {
    if (data_ != nullptr) {
        secure_scrub(data_, size_);
    }
}

void SecureBuffer::resize(size_type new_size) {
    if (new_size == size_) {
        return;  // nothing to do
    }

    // Strong exception guarantee: allocate the new region FIRST. If `new`
    // throws, we have not yet touched data_/size_, so the original buffer (and
    // its secret) is left fully intact.
    value_type* new_data = nullptr;
    if (new_size > 0) {
        new_data = new value_type[new_size];  // may throw std::bad_alloc
        secure_scrub(new_data, new_size);     // zero the whole new region

        // Copy over the surviving prefix (min of old and new sizes).
        if (data_ != nullptr) {
            std::copy(data_, data_ + std::min(size_, new_size), new_data);
        }
    }

    // Only now that the new region is ready do we scrub + release the old one,
    // so the discarded tail (if shrinking) is zeroized before it is freed.
    if (data_ != nullptr) {
        secure_scrub(data_, size_);
        delete[] data_;
    }

    data_ = new_data;
    size_ = new_size;
}

}  // namespace mtls_core
