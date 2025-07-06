#pragma once
#include <windows.h>
#include <vector>
#include <string>

struct ProcessWhitelist {
    std::wstring process_name;
    std::wstring publisher;
    std::wstring description;
};

struct CheatSignature {
    std::vector<BYTE> pattern;
    std::string name;
    int confidence_weight;
    bool require_context;
};

// Function declarations
void scan_signature_cheat();
bool advanced_signature_search(const BYTE* data, SIZE_T size, const CheatSignature& signature);
bool verify_cheat_context(const BYTE* data, SIZE_T size, SIZE_T found_offset);
bool is_process_whitelisted(const std::wstring& process_name);
bool is_memory_region_safe(const MEMORY_BASIC_INFORMATION& mbi);
int calculate_threat_score(const std::vector<std::string>& detected_signatures);
std::vector<std::string> get_running_processes();