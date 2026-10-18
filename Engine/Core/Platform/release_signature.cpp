#include "release_signature.h"

#include <monocypher.h>
#include <monocypher-ed25519.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <stdexcept>
#include <string>
#include <vector>

namespace dingosdk::launcher {
namespace {

[[noreturn]] void fail(const std::string& message) { throw std::runtime_error(message); }

// Strict base64: the standard alphabet, padded, nothing else.
std::vector<std::uint8_t> base64(std::string_view text) {
    const auto value = [](char c) -> int {
        if (c >= 'A' && c <= 'Z') return c - 'A';
        if (c >= 'a' && c <= 'z') return c - 'a' + 26;
        if (c >= '0' && c <= '9') return c - '0' + 52;
        if (c == '+') return 62;
        if (c == '/') return 63;
        return -1;
    };
    if (text.empty() || text.size() % 4) fail("signature data is not base64");
    std::vector<std::uint8_t> out;
    for (std::size_t at = 0; at < text.size(); at += 4) {
        const bool last = at + 4 == text.size();
        const int pad = last ? (text[at + 3] == '=') + (text[at + 2] == '=') : 0;
        std::uint32_t group{};
        for (int i = 0; i < 4; ++i) {
            const int digit = i >= 4 - pad ? 0 : value(text[at + i]);
            if (digit < 0) fail("signature data is not base64");
            group = group << 6 | static_cast<std::uint32_t>(digit);
        }
        out.push_back(static_cast<std::uint8_t>(group >> 16));
        if (pad < 2) out.push_back(static_cast<std::uint8_t>(group >> 8));
        if (pad < 1) out.push_back(static_cast<std::uint8_t>(group));
    }
    return out;
}

// The .minisig file's four lines, without their line endings.
std::array<std::string_view, 4> lines(std::string_view text) {
    std::array<std::string_view, 4> out{};
    for (auto& line : out) {
        const auto end = text.find('\n');
        line = text.substr(0, end);
        if (line.ends_with('\r')) line.remove_suffix(1);
        text = end == std::string_view::npos ? std::string_view{} : text.substr(end + 1);
    }
    if (text.find_first_not_of("\r\n") != std::string_view::npos) fail("the signature has extra lines");
    return out;
}

} // namespace

void verify_minisign(std::string_view message, std::string_view signature, std::string_view public_key) {
    // Public key: "Ed", an 8-byte key id, the 32-byte Ed25519 key.
    const auto key = base64(public_key);
    if (key.size() != 42 || key[0] != 'E' || key[1] != 'd') fail("the built-in public key is not a minisign key");
    const auto [untrusted, encoded, trusted, encoded_global] = lines(signature);
    constexpr std::string_view trusted_prefix = "trusted comment: ";
    if (!untrusted.starts_with("untrusted comment:") || !trusted.starts_with(trusted_prefix))
        fail("the signature is not a minisign signature");
    // Signature: "ED" (BLAKE2b-512 of the file signed) or legacy "Ed", the key id, 64 bytes.
    const auto sig = base64(encoded);
    if (sig.size() != 74 || sig[0] != 'E' || (sig[1] != 'D' && sig[1] != 'd'))
        fail("the signature uses an unknown algorithm");
    if (!std::equal(sig.begin() + 2, sig.begin() + 10, key.begin() + 2))
        fail("the signature was made with a different key");
    const auto* pk = key.data() + 10;
    const auto* bytes = reinterpret_cast<const std::uint8_t*>(message.data());
    int bad{};
    if (sig[1] == 'D') {
        std::array<std::uint8_t, 64> hash{};
        crypto_blake2b(hash.data(), hash.size(), bytes, message.size());
        bad = crypto_ed25519_check(sig.data() + 10, pk, hash.data(), hash.size());
    } else {
        bad = crypto_ed25519_check(sig.data() + 10, pk, bytes, message.size());
    }
    if (bad) fail("the signature does not match");
    // The global signature covers the signature and the trusted comment together.
    const auto global = base64(encoded_global);
    const auto comment = trusted.substr(trusted_prefix.size());
    std::vector<std::uint8_t> signed_part(sig.begin() + 10, sig.end());
    signed_part.insert(signed_part.end(), comment.begin(), comment.end());
    if (global.size() != 64 || crypto_ed25519_check(global.data(), pk, signed_part.data(), signed_part.size()))
        fail("the signature's trusted comment does not match");
}

void check_launcher_json(std::string_view json, const std::optional<std::string>& signature,
                         std::string_view public_key) {
    if (public_key.empty()) return;
    if (!signature) fail("launcher.json is not signed (no launcher.json.minisig)");
    try {
        verify_minisign(json, *signature, public_key);
    } catch (const std::exception& exception) {
        fail(std::string("launcher.json's signature is rejected: ") + exception.what());
    }
}

} // namespace dingosdk::launcher
