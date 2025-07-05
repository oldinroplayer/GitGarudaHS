#pragma once

#include <windows.h>
#include <vector>
#include <string>
#include <set>

// Struktur untuk menyimpan informasi signature
struct CheatSignature {
    std::vector<BYTE> pattern;
    std::string name;
    int confidence_weight;
    bool require_context;
};

// Struktur untuk whitelist proses
struct ProcessWhitelist {
    std::wstring process_name;
    std::wstring company_name;
    std::wstring description;
};

void scan_signature_cheat();
bool is_process_whitelisted(const std::wstring& process_name);
bool verify_cheat_context(const BYTE* data, SIZE_T size, SIZE_T found_offset);
int calculate_threat_score(const std::vector<std::string>& detected_signatures);
bool is_memory_region_safe(const MEMORY_BASIC_INFORMATION& mbi);
bool advanced_signature_search(const BYTE* data, SIZE_T size, const CheatSignature& signature);
std::vector<std::string> get_running_processes();
bool is_development_environment();