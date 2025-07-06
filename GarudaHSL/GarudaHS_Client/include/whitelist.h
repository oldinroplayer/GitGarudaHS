#pragma once
#include <windows.h>
#include <string>
#include <vector>
#include <set>
#include <map>

// Intelligent whitelisting system to reduce false positives
class IntelligentWhitelist {
private:
    // Static whitelists
    static std::set<std::wstring> legitimate_processes;
    static std::set<std::wstring> legitimate_window_classes;
    static std::set<std::wstring> legitimate_window_titles;
    static std::set<std::wstring> legitimate_modules;
    
    // Dynamic learning system
    static std::map<std::wstring, int> process_reputation;
    static std::map<std::wstring, int> module_reputation;
    
    // System analysis
    static bool is_system_signed(const std::wstring& file_path);
    static bool is_microsoft_signed(const std::wstring& file_path);
    static bool is_known_antivirus(const std::wstring& process_name);
    static bool is_development_tool(const std::wstring& process_name);
    static bool is_system_service(const std::wstring& process_name);

public:
    // Initialization
    static void Initialize();
    static void LoadDynamicWhitelist();
    static void SaveDynamicWhitelist();
    
    // Process checking
    static bool IsProcessWhitelisted(const std::wstring& process_name);
    static bool IsProcessLegitimate(const std::wstring& process_path);
    
    // Module checking
    static bool IsModuleWhitelisted(const std::wstring& module_path);
    static bool IsModuleLegitimate(const std::wstring& module_path);
    
    // Window checking
    static bool IsWindowLegitimate(HWND hwnd);
    static bool IsWindowClassLegitimate(const std::wstring& class_name);
    static bool IsWindowTitleLegitimate(const std::wstring& title);
    
    // Reputation system
    static void UpdateProcessReputation(const std::wstring& process_name, bool is_legitimate);
    static void UpdateModuleReputation(const std::wstring& module_path, bool is_legitimate);
    static int GetProcessReputation(const std::wstring& process_name);
    static int GetModuleReputation(const std::wstring& module_path);
    
    // System environment detection
    static bool IsRunningInVM();
    static bool IsRunningInSandbox();
    static bool IsDebuggingEnvironment();
    static bool IsTestingEnvironment();
    
    // Cleanup
    static void Cleanup();
};

// Helper functions
bool is_legitimate_overlay_process(const std::wstring& process_name);
bool is_legitimate_injection_source(const std::wstring& module_path);
bool should_skip_process_monitoring(const std::wstring& process_name);
bool should_skip_memory_region(PVOID address, SIZE_T size);
