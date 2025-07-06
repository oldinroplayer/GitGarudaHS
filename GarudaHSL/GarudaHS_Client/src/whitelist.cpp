#include "whitelist.h"
#include <algorithm>
#include <fstream>
#include <iostream>
#include <wintrust.h>
#include <softpub.h>
#include <wincrypt.h>

#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "crypt32.lib")

// Static member definitions
std::set<std::wstring> IntelligentWhitelist::legitimate_processes;
std::set<std::wstring> IntelligentWhitelist::legitimate_window_classes;
std::set<std::wstring> IntelligentWhitelist::legitimate_window_titles;
std::set<std::wstring> IntelligentWhitelist::legitimate_modules;
std::map<std::wstring, int> IntelligentWhitelist::process_reputation;
std::map<std::wstring, int> IntelligentWhitelist::module_reputation;

void IntelligentWhitelist::Initialize() {
    // Initialize legitimate processes
    legitimate_processes = {
        // System processes
        L"system", L"smss.exe", L"csrss.exe", L"wininit.exe", L"winlogon.exe",
        L"services.exe", L"lsass.exe", L"svchost.exe", L"explorer.exe",
        L"dwm.exe", L"taskhost.exe", L"conhost.exe", L"spoolsv.exe",
        
        // Common legitimate applications
        L"discord.exe", L"steam.exe", L"chrome.exe", L"firefox.exe",
        L"msedge.exe", L"notepad.exe", L"calc.exe", L"mspaint.exe",
        
        // Gaming platforms
        L"origin.exe", L"uplay.exe", L"epicgameslauncher.exe", L"battle.net.exe",
        L"gog.exe", L"playnite.exe",
        
        // Streaming/Recording
        L"obs64.exe", L"obs32.exe", L"streamlabs obs.exe", L"xsplit.exe",
        L"bandicam.exe", L"fraps.exe", L"shadowplay.exe",
        
        // Hardware monitoring
        L"msiafterburner.exe", L"hwinfo64.exe", L"cpuz.exe", L"gpuz.exe",
        L"coretemp.exe", L"speedfan.exe",
        
        // Antivirus (common ones)
        L"avp.exe", L"avgui.exe", L"avguard.exe", L"mbam.exe",
        L"msmpeng.exe", L"windefend.exe"
    };
    
    // Initialize legitimate window classes
    legitimate_window_classes = {
        L"tooltips_class32", L"#32768", L"#32769", L"#32770", L"#32771",
        L"shell_traywnd", L"progman", L"workerw", L"button", L"edit",
        L"static", L"listbox", L"combobox", L"scrollbar", L"mdiclient",
        L"dwmwindow", L"applicationframewindow", L"windows.ui.core.corewindow"
    };
    
    // Initialize legitimate window title patterns
    legitimate_window_titles = {
        L"program manager", L"desktop", L"taskbar", L"start menu",
        L"notification area", L"system tray", L"volume control",
        L"network", L"battery", L"clock", L"calendar"
    };
    
    LoadDynamicWhitelist();
}

bool IntelligentWhitelist::is_microsoft_signed(const std::wstring& file_path) {
    WINTRUST_FILE_INFO file_info = {};
    file_info.cbStruct = sizeof(WINTRUST_FILE_INFO);
    file_info.pcwszFilePath = file_path.c_str();
    
    WINTRUST_DATA trust_data = {};
    trust_data.cbStruct = sizeof(WINTRUST_DATA);
    trust_data.dwUIChoice = WTD_UI_NONE;
    trust_data.fdwRevocationChecks = WTD_REVOKE_NONE;
    trust_data.dwUnionChoice = WTD_CHOICE_FILE;
    trust_data.pFile = &file_info;
    
    GUID policy_guid = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    LONG result = WinVerifyTrust(NULL, &policy_guid, &trust_data);
    
    return result == ERROR_SUCCESS;
}

bool IntelligentWhitelist::is_known_antivirus(const std::wstring& process_name) {
    std::wstring lower_name = process_name;
    std::transform(lower_name.begin(), lower_name.end(), lower_name.begin(), ::tolower);
    
    std::vector<std::wstring> av_patterns = {
        L"antivirus", L"kaspersky", L"norton", L"mcafee", L"avg", L"avast",
        L"bitdefender", L"eset", L"trend", L"sophos", L"malwarebytes",
        L"defender", L"security", L"firewall"
    };
    
    for (const auto& pattern : av_patterns) {
        if (lower_name.find(pattern) != std::wstring::npos) {
            return true;
        }
    }
    
    return false;
}

bool IntelligentWhitelist::is_development_tool(const std::wstring& process_name) {
    std::wstring lower_name = process_name;
    std::transform(lower_name.begin(), lower_name.end(), lower_name.begin(), ::tolower);
    
    std::vector<std::wstring> dev_patterns = {
        L"devenv", L"code", L"visual studio", L"intellij", L"eclipse",
        L"netbeans", L"atom", L"sublime", L"notepad++", L"vim", L"emacs"
    };
    
    for (const auto& pattern : dev_patterns) {
        if (lower_name.find(pattern) != std::wstring::npos) {
            return true;
        }
    }
    
    return false;
}

bool IntelligentWhitelist::IsProcessWhitelisted(const std::wstring& process_name) {
    std::wstring lower_name = process_name;
    std::transform(lower_name.begin(), lower_name.end(), lower_name.begin(), ::tolower);
    
    // Check static whitelist
    if (legitimate_processes.find(lower_name) != legitimate_processes.end()) {
        return true;
    }
    
    // Check if it's a known antivirus
    if (is_known_antivirus(lower_name)) {
        return true;
    }
    
    // Check if it's a development tool
    if (is_development_tool(lower_name)) {
        return true;
    }
    
    // Check reputation system
    int reputation = GetProcessReputation(lower_name);
    if (reputation >= 5) { // High positive reputation
        return true;
    }
    
    return false;
}

bool IntelligentWhitelist::IsWindowLegitimate(HWND hwnd) {
    // Get window class
    wchar_t className[256];
    if (GetClassNameW(hwnd, className, sizeof(className) / sizeof(wchar_t))) {
        std::wstring classStr(className);
        std::transform(classStr.begin(), classStr.end(), classStr.begin(), ::tolower);
        
        if (legitimate_window_classes.find(classStr) != legitimate_window_classes.end()) {
            return true;
        }
    }
    
    // Get window title
    wchar_t title[256];
    if (GetWindowTextW(hwnd, title, sizeof(title) / sizeof(wchar_t))) {
        std::wstring titleStr(title);
        std::transform(titleStr.begin(), titleStr.end(), titleStr.begin(), ::tolower);
        
        for (const auto& legit_title : legitimate_window_titles) {
            if (titleStr.find(legit_title) != std::wstring::npos) {
                return true;
            }
        }
    }
    
    // Check if window belongs to whitelisted process
    DWORD processId;
    GetWindowThreadProcessId(hwnd, &processId);
    
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, processId);
    if (hProcess) {
        wchar_t processPath[MAX_PATH];
        DWORD size = MAX_PATH;
        if (QueryFullProcessImageNameW(hProcess, 0, processPath, &size)) {
            std::wstring processName = processPath;
            size_t pos = processName.find_last_of(L"\\");
            if (pos != std::wstring::npos) {
                processName = processName.substr(pos + 1);
            }
            
            CloseHandle(hProcess);
            return IsProcessWhitelisted(processName);
        }
        CloseHandle(hProcess);
    }
    
    return false;
}

void IntelligentWhitelist::LoadDynamicWhitelist() {
    // Load reputation data from file (simplified implementation)
    // In a real implementation, this would load from encrypted file
}

void IntelligentWhitelist::SaveDynamicWhitelist() {
    // Save reputation data to file (simplified implementation)
}

int IntelligentWhitelist::GetProcessReputation(const std::wstring& process_name) {
    auto it = process_reputation.find(process_name);
    return (it != process_reputation.end()) ? it->second : 0;
}

void IntelligentWhitelist::UpdateProcessReputation(const std::wstring& process_name, bool is_legitimate) {
    int& reputation = process_reputation[process_name];
    if (is_legitimate) {
        reputation = min(reputation + 1, 10); // Cap at 10
    } else {
        reputation = max(reputation - 2, -10); // Floor at -10
    }
}

void IntelligentWhitelist::Cleanup() {
    SaveDynamicWhitelist();
    legitimate_processes.clear();
    legitimate_window_classes.clear();
    legitimate_window_titles.clear();
    legitimate_modules.clear();
    process_reputation.clear();
    module_reputation.clear();
}

// Helper function implementations
bool is_legitimate_overlay_process(const std::wstring& process_name) {
    return IntelligentWhitelist::IsProcessWhitelisted(process_name);
}

bool should_skip_process_monitoring(const std::wstring& process_name) {
    return IntelligentWhitelist::IsProcessWhitelisted(process_name);
}
