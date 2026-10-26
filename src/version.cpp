// -----------------------------------------------------------------------------
// version.cpp
//
// Implements mtls_core::version_string(). The version literal is kept in sync
// with the VERSION in CMakeLists.txt (project(... VERSION 0.1.0)). A string
// literal has static storage duration, so returning a pointer to it is safe for
// the whole program lifetime — no heap, no cleanup.
// -----------------------------------------------------------------------------

#include "mtls_core/version.hpp"

namespace mtls_core {

const char* version_string() noexcept {
    return "0.1.0";
}

}  // namespace mtls_core
