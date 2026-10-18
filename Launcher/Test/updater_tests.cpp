// Launcher self-update: launcher.json parsing and the DepotDownloader.exe pin.
#include "Launcher/updater.h"
#include "Engine/Core/Platform/launcher_support.h"

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
