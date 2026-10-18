#pragma once

#include <optional>
#include <string>
#include <string_view>

// The minisign signature a release carries for its launcher.json (launcher.json.minisig).
// The launcher and the dedicated server check it against the public key built in.
namespace dingosdk::launcher {

// Throws with the reason unless `signature` (the .minisig file's text) is a valid minisign
// signature of `message` by `public_key` (the base64 line of a minisign .pub file), its
// trusted comment included. Both the prehashed ("ED") and legacy ("Ed") forms are accepted.
void verify_minisign(std::string_view message, std::string_view signature, std::string_view public_key);

// launcher.json against the key built in (`public_key`, empty in a local build without one).
// With a key, a missing (nullopt) or bad signature throws; without one this does nothing.
void check_launcher_json(std::string_view json, const std::optional<std::string>& signature,
                         std::string_view public_key);

} // namespace dingosdk::launcher
