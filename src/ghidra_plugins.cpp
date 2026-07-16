#include <vector>
#include <string>
#include <unistd.h>
#include "ghidra_plugins.h"
#include <filesystem>
#include <fstream>
#include <iostream>
#include <cstdlib>
#include <sstream>
#include <algorithm>

namespace fs = std::filesystem;

const PluginInfo PLUGIN_EMOTIONENGINE = {
    "Emotion Engine Reloaded",
    "PS2 Emotion Engine processor + decompiler (MIPS R5900, VU0, COP0/1/2)",
    "ghidra-emotionengine-reloaded.zip",
    "https://github.com/chaoticgd/ghidra-emotionengine-reloaded/releases/latest",
    "v2.1.36"
};

static std::string get_extensions_dir(const GhidraInfo& ghidra) {
    // Check if path itself has Extensions/Ghidra
    auto direct = fs::path(ghidra.path) / "Extensions" / "Ghidra";
    if (fs::is_directory(direct)) return direct.string();

    // Check ghidra_* subdirectories
    for (auto& p : fs::directory_iterator(ghidra.path)) {
        std::string name = p.path().filename().string();
        if (name.find("ghidra") != std::string::npos && p.is_directory()) {
            auto ext = p.path() / "Extensions" / "Ghidra";
            if (fs::is_directory(ext)) return ext.string();
        }
    }

    // Check parent directory (user might have pointed to Ghidra/support)
    auto parent = fs::path(ghidra.path).parent_path();
    auto parent_ext = parent / "Extensions" / "Ghidra";
    if (fs::is_directory(parent_ext)) return parent_ext.string();

    // Check Ghidra/ subdirectory (common layout: Ghidra/Ghidra/Extensions/Ghidra)
    auto ghidra_sub = fs::path(ghidra.path) / "Ghidra" / "Extensions" / "Ghidra";
    if (fs::is_directory(ghidra_sub)) return ghidra_sub.string();

    return "";
}

static bool dir_contains_extension(const std::string& ext_dir, const std::string& plugin_name) {
    if (!fs::is_directory(ext_dir)) return false;

    // Normalize plugin name: lowercase, replace spaces with hyphens
    std::string normalized_plugin = plugin_name;
    std::transform(normalized_plugin.begin(), normalized_plugin.end(), normalized_plugin.begin(), ::tolower);
    std::replace(normalized_plugin.begin(), normalized_plugin.end(), ' ', '-');

    for (auto& p : fs::directory_iterator(ext_dir)) {
        std::string name = p.path().filename().string();
        std::string lower_name = name;
        std::transform(lower_name.begin(), lower_name.end(), lower_name.begin(), ::tolower);

        // Check if directory name contains the normalized plugin name
        if (lower_name.find(normalized_plugin) != std::string::npos ||
            lower_name.find("emotionengine") != std::string::npos ||
            lower_name.find("emotion-engine") != std::string::npos) {
            if (p.is_directory()) return true;
            for (auto& sub : fs::directory_iterator(p.path())) {
                if (sub.is_directory()) return true;
            }
        }
    }
    return false;
}

bool check_plugin_installed(const GhidraInfo& ghidra, const PluginInfo& plugin) {
    std::string ext_dir = get_extensions_dir(ghidra);
    if (ext_dir.empty()) return false;
    return dir_contains_extension(ext_dir, plugin.name);
}

static std::string find_bundled_zip(const PluginInfo& plugin) {
    char exe_path[4096];
    ssize_t len = readlink("/proc/self/exe", exe_path, sizeof(exe_path) - 1);
    if (len <= 0) return "";
    exe_path[len] = '\0';
    fs::path bin_dir = fs::path(exe_path).parent_path();
    std::vector<fs::path> search = {
        bin_dir / "plugins" / plugin.zip_filename,
        bin_dir.parent_path() / "plugins" / plugin.zip_filename,
        bin_dir / ".." / "plugins" / plugin.zip_filename,
        "/usr/share/ps2-tool/plugins" / fs::path(plugin.zip_filename),
        "/usr/local/share/ps2-tool/plugins" / fs::path(plugin.zip_filename),
    };
    for (auto& p : search) {
        if (fs::exists(p)) return p.string();
    }
    return "";
}

static bool unzip_to(const std::string& zip_path, const std::string& dest_dir) {
    std::string cmd = "unzip -q -o \"" + zip_path + "\" -d \"" + dest_dir + "\" 2>&1";
    return system(cmd.c_str()) == 0;
}

bool install_plugin(const GhidraInfo& ghidra, const PluginInfo& plugin) {
    std::string ext_dir = get_extensions_dir(ghidra);
    if (ext_dir.empty()) {
        std::cerr << "  ERROR: Cannot find Ghidra Extensions directory\n";
        return false;
    }
    fs::create_directories(ext_dir);
    std::string zip_path = find_bundled_zip(plugin);
    if (zip_path.empty()) {
        std::cout << "  Plugin not bundled, downloading...\n";
        std::string dl = "curl -sL \"" + plugin.download_url + "\" -o /tmp/" + plugin.zip_filename;
        if (system(dl.c_str()) == 0 && fs::exists("/tmp/" + plugin.zip_filename))
            zip_path = "/tmp/" + plugin.zip_filename;
    }
    if (zip_path.empty()) {
        std::cerr << "  ERROR: Plugin ZIP not found: " << plugin.zip_filename << "\n";
        return false;
    }
    std::cout << "  Installing " << plugin.name << "...\n";
    if (!unzip_to(zip_path, ext_dir)) {
        std::cerr << "  ERROR: Failed to extract\n";
        return false;
    }
    std::cout << "  OK\n";
    return true;
}

bool check_and_install_all(const GhidraInfo& ghidra) {
    std::vector<PluginInfo> plugins = {PLUGIN_EMOTIONENGINE};
    bool all_ok = true;
    for (auto& plugin : plugins) {
        if (check_plugin_installed(ghidra, plugin)) {
            std::cout << "  " << plugin.name << ": OK\n";
        } else {
            std::cout << "  " << plugin.name << ": NOT FOUND\n";
            std::cout << "  Install " << plugin.name << "? [Y/n] ";
            std::string answer;
            std::getline(std::cin, answer);
            if (answer.empty() || answer[0] == 'y' || answer[0] == 'Y') {
                if (!install_plugin(ghidra, plugin)) all_ok = false;
            } else {
                std::cout << "  Skipped\n";
                all_ok = false;
            }
        }
    }
    return all_ok;
}
