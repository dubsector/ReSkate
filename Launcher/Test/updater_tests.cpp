// Launcher self-update: launcher.json parsing, the DepotDownloader.exe pin and its signature.
#include "Launcher/updater.h"
#include "Engine/Core/Platform/launcher_support.h"
#include "Engine/Core/Platform/release_signature.h"

#include <Windows.h>

#include <fstream>
#include <iostream>
#include <string>

namespace fs = std::filesystem;
using namespace dingosdk;

namespace {

int failures = 0;

void check(bool condition, const char* what) {
    if (condition) return;
    std::cerr << "FAIL: " << what << '\n';
    ++failures;
}

void write(const fs::path& path, std::string_view text) {
    fs::create_directories(path.parent_path());
    std::ofstream(path, std::ios::binary) << text;
}

const std::string zero(64, '0');
const std::string ones(64, '1');

// A launcher.json with every required part; `depot` is the depot_downloader section's extra fields.
std::string config_text(std::string_view depot) {
    return std::string(R"({"schema":1,"game":{"app_id":1,"depot_id":2,"manifest_id":"3","skate_sha256":")") + zero +
           R"("},"depot_downloader":{"url":"https://127.0.0.1:9/DepotDownloader.zip","sha256":")" + ones +
           R"(","size":10)" + std::string(depot) + "}}";
}

// Made with minisign 0.12 and a throwaway key used only here (minisign -G -W, then -S and
// -S -l for the legacy form, trusted comment "reskate updater test").
constexpr std::string_view test_key = "RWS7xq924Xd4dYmX+4Vr8JUJThpaoBTTx+h856mkDoBAW7KTgYWrWPoA";
constexpr std::string_view signed_text = "{\"schema\":1,\"note\":\"signed by the updater test key\"}\n";
constexpr std::string_view hashed_signature =
    "untrusted comment: signature from minisign secret key\n"
    "RUS7xq924Xd4dYwK+9vF9XypGfb+Jttk9EFnpAFWgbXJFJj9IkcdFQsZjo6tGiX+M/CE7RcMmEGrpyBXkhnL8KSFqJSjl2TFsgI=\n"
    "trusted comment: reskate updater test\n"
    "3CmSgjugE0SGUsMLHmkxNvSgJ8ogezjdMmOjQ/4BRWtwyA7l/Cr9lZdAtWTsf8pKGK/SK4Gq5R9CqUel9GPJCA==\n";
constexpr std::string_view legacy_signature =
    "untrusted comment: signature from minisign secret key\r\n"
    "RWS7xq924Xd4dXKeHr9L52dRnoTnbwehjy93fjxN7Z+msi8IY7mXpbFH0SUe9EWZISg7r60zAIDNKeTe0xFNiHUAXwI54rFLRQ0=\r\n"
    "trusted comment: reskate updater test\r\n"
    "NSoF9xKj/X/WhDrgjr64EbQFPFDTDPEwL5XINYyKJuayNO/X7jmOBYRskhY11GUUqzVQlxP9zwjD8XgK/oUCAg==\r\n";
// minisign's own release key, a real key that did not sign the fixture.
constexpr std::string_view other_key = "RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3";

bool verifies(std::string_view message, std::string_view signature, std::string_view key = test_key) {
    try {
        launcher::verify_minisign(message, signature, key);
        return true;
    } catch (const std::exception&) {
        return false;
    }
}

std::string replaced(std::string_view text, std::string_view from, std::string_view to) {
    std::string out(text);
    out.replace(out.find(from), from.size(), to);
    return out;
}

bool parses(const std::string& text) {
    try {
        launcher_update::parse_config(text);
        return true;
    } catch (const std::exception&) {
        return false;
    }
}

} // namespace

int main() {
    wchar_t temp[MAX_PATH]{};
    GetTempPathW(MAX_PATH, temp);
    const auto root = fs::path(temp) / (L"reskate-updater-tests-" + std::to_wstring(GetCurrentProcessId()));
    fs::remove_all(root);
    fs::create_directories(root);
    SetEnvironmentVariableW(L"LOCALAPPDATA", root.c_str());

    // The DepotDownloader.exe pin is required and must be a SHA-256.
    check(!parses(config_text("")), "A config without depot_downloader.exe_sha256 is refused");
    check(!parses(config_text(R"(,"exe_sha256":"ABC")")), "A malformed depot_downloader.exe_sha256 is refused");
    const auto config = launcher_update::parse_config(config_text(R"(,"exe_sha256":")" + zero + "\""));
    check(config.depot_downloader_exe_sha256 == zero, "depot_downloader.exe_sha256 is read");

    // launcher.json.minisig: minisign's prehashed and legacy signatures, and what must fail.
    check(verifies(signed_text, hashed_signature), "A prehashed minisign signature verifies");
    check(verifies(signed_text, legacy_signature), "A legacy minisign signature with CRLF lines verifies");
    check(!verifies(replaced(signed_text, "1", "2"), hashed_signature), "A changed file is refused");
    check(!verifies(signed_text, hashed_signature, other_key), "Another key's check is refused");
    check(!verifies(signed_text, replaced(hashed_signature, "updater test", "updater tesT")),
        "A changed trusted comment is refused");
    check(!verifies(signed_text, replaced(hashed_signature, "RUS7", "RXS7")), "A damaged signature line is refused");
    check(!verifies(signed_text, std::string(hashed_signature) + "extra\n"), "Extra lines are refused");
    check(!verifies(signed_text, ""), "An empty signature is refused");
    check(!verifies(signed_text, hashed_signature, "RWS7xq924Xd4dYmX"), "A short key is refused");
    bool unsigned_refused{};
    try {
        launcher::check_launcher_json(signed_text, std::nullopt, test_key);
    } catch (const std::exception&) {
        unsigned_refused = true;
    }
    check(unsigned_refused, "With a key built in, an unsigned launcher.json is refused");
    try {
        launcher::check_launcher_json(signed_text, std::string(hashed_signature), test_key);
        launcher::check_launcher_json(signed_text, std::nullopt, "");
    } catch (const std::exception& exception) {
        check(false, exception.what());
    }

    // A cached copy that matches the pin is used as it is, without a download.
    const auto folder = root / L"ReSkate" / L"tools" / L"DepotDownloader" / ones.substr(0, 16);
    const auto exe = folder / L"DepotDownloader.exe";
    write(exe, "the pinned DepotDownloader");
    const auto pinned = launcher::sha256_file(exe);
    try {
        check(launcher_update::ensure_depot_downloader(config.depot_downloader, pinned) == exe,
            "A matching DepotDownloader.exe is used");
    } catch (const std::exception& exception) {
        check(false, exception.what());
    }

    // A copy changed since it was unpacked is removed and fetched again (here the download
    // fails, as nothing listens there), never started.
    write(exe, "a swapped DepotDownloader");
    bool refused{};
    try {
        launcher_update::ensure_depot_downloader(config.depot_downloader, pinned);
    } catch (const std::exception&) {
        refused = true;
    }
    check(refused, "A mismatched DepotDownloader.exe is not returned");
    check(!fs::exists(exe), "A mismatched DepotDownloader.exe is deleted");

    bool unpinned{};
    try {
        launcher_update::ensure_depot_downloader(config.depot_downloader, "");
    } catch (const std::exception&) {
        unpinned = true;
    }
    check(unpinned, "Without a pin DepotDownloader is not used");

    fs::remove_all(root);
    if (failures) {
        std::cerr << failures << " updater check(s) failed\n";
        return 1;
    }
    std::cout << "updater tests passed\n";
    return 0;
}
