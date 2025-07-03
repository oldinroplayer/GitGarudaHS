#include "pch.h"
#include <stud_pe.h>

namespace stud_pe {
    // implementasi dummy untuk sementara
    bool ImportDLL(const char* targetExePath, const char* dllPath) {
        // nanti diganti dengan panggilan Stud_PE asli
        return true;
    }
}

extern "C" __declspec(dllexport)
void HookEntry()
{
    stud_pe::ImportDLL("RRO.exe", "GarudaHS.dll");
}