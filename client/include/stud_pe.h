#pragma once

#include <windows.h>

namespace stud_pe {
    // Import DLL ke target exe; 
    // return true jika sukses, false kalau gagal
    bool ImportDLL(const char* targetExePath, const char* dllPath);
}