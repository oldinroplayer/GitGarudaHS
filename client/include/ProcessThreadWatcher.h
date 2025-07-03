#pragma once

#include <windows.h>
#include <string>
#include <vector>

namespace GarudaHS {

    struct ProcInfo {
        DWORD pid;
        std::wstring exeName;
    };

    class ProcessThreadWatcher {
    public:
        static void Initialize();
        static void Tick();

    private:
        static std::vector<ProcInfo> knownProcs;  // jangan lupa ';'
        static std::vector<ProcInfo> EnumerateProcesses();
        static void OnNewProcess(const ProcInfo& pi);
    };

}
