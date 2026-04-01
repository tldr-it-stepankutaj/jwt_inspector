#pragma once

#include <string>

namespace jwt_inspector {

/// Decode and display JWT token contents.
/// If json_output is true, emit structured JSON to stdout.
void decode_token(const std::string& token, bool json_output = false);

} // namespace jwt_inspector
