#pragma once
#include "ghidra_detect.h"
#include <string>

struct PluginInfo {
    std::string name;
    std::string description;
    std::string zip_filename;
    std::string download_url;
    std::string version;
};

extern const PluginInfo PLUGIN_EMOTIONENGINE;

bool check_plugin_installed(const GhidraInfo& ghidra, const PluginInfo& plugin);
bool install_plugin(const GhidraInfo& ghidra, const PluginInfo& plugin);
bool check_and_install_all(const GhidraInfo& ghidra);
