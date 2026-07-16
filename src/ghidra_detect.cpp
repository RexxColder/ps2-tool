#include <vector>
#include <string>
#include "ghidra_detect.h"
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <algorithm>

namespace fs = std::filesystem;

static std::string exec_cmd(const std::string& cmd) {
    FILE* pipe = popen(cmd.c_str(), "r");
    if (!pipe) return "";
    char buf[256];
    std::string result;
    while (fgets(buf, sizeof(buf), pipe)) result += buf;
    pclose(pipe);
    // trim
    while (!result.empty() && (result.back() == '\n' || result.back() == '\r'))
        result.pop_back();
    return result;
}

static std::string extract_version(const std::string& path) {
    // Try to read version from Ghidra's application.properties
    for (auto& p : fs::directory_iterator(path)) {
        if (p.path().filename().string().find("ghidra_") == 0 && p.is_directory()) {
            auto props = p.path() / "application.properties";
            if (fs::exists(props)) {
                std::ifstream f(props);
                std::string line;
                while (std::getline(f, line)) {
                    if (line.find("application.version") != std::string::npos) {
                        auto eq = line.find('=');
                        if (eq != std::string::npos) {
                            std::string v = line.substr(eq + 1);
                            // trim whitespace
                            while (!v.empty() && v.front() == ' ') v.erase(0, 1);
                            while (!v.empty() && v.back() == ' ') v.pop_back();
                            return v;
                        }
                    }
                }
            }
            // Fallback: extract from dirname
            std::string dname = p.path().filename().string();
            auto pos = dname.find("ghidra_");
            if (pos != std::string::npos) {
                std::string ver = dname.substr(pos + 7);
                auto end = ver.find("_PUBLIC");
                if (end != std::string::npos) ver = ver.substr(0, end);
                return ver;
            }
        }
    }
    return "unknown";
}

static std::string find_headless(const std::string& ghidra_path) {
    for (auto& p : fs::directory_iterator(ghidra_path)) {
        if (p.path().filename().string().find("ghidra_") == 0 && p.is_directory()) {
            auto headless = p.path() / "support" / "analyzeHeadless";
            if (fs::exists(headless)) return headless.string();
            // Try .bat for cross-platform
            auto headless_bat = p.path() / "support" / "analyzeHeadless.bat";
            if (fs::exists(headless_bat)) return headless_bat.string();
        }
    }
    return "";
}

GhidraInfo find_ghidra() {
    GhidraInfo info;

    // Check if Java is available
    std::string java_check = exec_cmd("which java 2>/dev/null");
    info.has_java = !java_check.empty();

    // Search paths
    std::vector<std::string> search_paths;

    // 1. $GHIDRA_HOME
    char* ghidra_home = std::getenv("GHIDRA_HOME");
    if (ghidra_home && fs::is_directory(ghidra_home)) {
        search_paths.push_back(ghidra_home);
    }

    // 2. Common locations
    search_paths.push_back("/opt/ghidra");
    search_paths.push_back(std::string(std::getenv("HOME") ? std::getenv("HOME") : "") + "/ghidra");
    search_paths.push_back("/usr/local/ghidra");
    search_paths.push_back(std::string(std::getenv("HOME") ? std::getenv("HOME") : "") + "/.local/share/ghidra");

    // 3. Search /opt for ghidra_* directories
    if (fs::is_directory("/opt")) {
        for (auto& p : fs::directory_iterator("/opt")) {
            std::string name = p.path().filename().string();
            if (name.find("ghidra_") == 0 && p.is_directory()) {
                search_paths.push_back(p.path().string());
            }
        }
    }

    // 4. Search home directory
    char* home = std::getenv("HOME");
    if (home && fs::is_directory(home)) {
        for (auto& p : fs::directory_iterator(home)) {
            std::string name = p.path().filename().string();
            if (name.find("ghidra_") == 0 && p.is_directory()) {
                search_paths.push_back(p.path().string());
            }
        }
    }

    // 5. Check $PATH for analyzeHeadless
    std::string path_env = std::getenv("PATH") ? std::getenv("PATH") : "";
    std::istringstream ss(path_env);
    std::string token;
    while (std::getline(ss, token, ':')) {
        auto headless = fs::path(token) / "analyzeHeadless";
        if (fs::exists(headless)) {
            // Resolve parent directory
            search_paths.push_back(fs::canonical(headless).parent_path().parent_path().string());
        }
    }

    // Deduplicate and search
    std::sort(search_paths.begin(), search_paths.end());
    search_paths.erase(std::unique(search_paths.begin(), search_paths.end()), search_paths.end());

    for (auto& sp : search_paths) {
        if (!fs::is_directory(sp)) continue;
        std::string headless = find_headless(sp);
        if (!headless.empty()) {
            info.found = true;
            info.path = sp;
            info.version = extract_version(sp);
            info.analyze_headless = headless;
            return info;
        }
    }

    return info;
}
