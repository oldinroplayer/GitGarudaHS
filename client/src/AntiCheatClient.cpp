#include "../include/GarudaHS.h"
#include <iostream>
#include <Windows.h>

namespace GarudaHS
{
    // Implementasi singleton pattern
    AntiCheatClient& AntiCheatClient::GetInstance()
    {
        static AntiCheatClient instance;
        return instance;
    }

    bool AntiCheatClient::Initialize()
    {
        if (m_initialized)
        {
            return true;
        }

        std::cout << "Menginisialisasi Garuda Hack Shield Client..." << std::endl;

        // Inisialisasi semua modul yang terdaftar
        for (auto& module : m_modules)
        {
            if (!module->Initialize())
            {
                std::cerr << "Gagal menginisialisasi modul: " << module->GetName() << std::endl;
                return false;
            }
            std::cout << "Modul " << module->GetName() << " berhasil diinisialisasi." << std::endl;
        }

        m_initialized = true;
        std::cout << "Garuda Hack Shield Client berhasil diinisialisasi." << std::endl;
        
        return true;
    }

    bool AntiCheatClient::Scan()
    {
        if (!m_initialized)
        {
            std::cerr << "AntiCheatClient belum diinisialisasi." << std::endl;
            return false;
        }

        bool result = true;

        // Jalankan scan pada semua modul
        for (auto& module : m_modules)
        {
            if (!module->Scan())
            {
                std::cerr << "Modul " << module->GetName() << " mendeteksi cheat." << std::endl;
                result = false;
                // Tidak return di sini agar semua modul tetap dijalankan
            }
        }

        return result;
    }

    void AntiCheatClient::Shutdown()
    {
        if (!m_initialized)
        {
            return;
        }

        std::cout << "Mematikan Garuda Hack Shield Client..." << std::endl;

        // Matikan semua modul
        for (auto& module : m_modules)
        {
            module->Shutdown();
            std::cout << "Modul " << module->GetName() << " berhasil dimatikan." << std::endl;
        }

        m_initialized = false;
        std::cout << "Garuda Hack Shield Client berhasil dimatikan." << std::endl;
    }

    void AntiCheatClient::RegisterModule(std::shared_ptr<IAntiCheatModule> module)
    {
        if (module)
        {
            m_modules.push_back(module);
            std::cout << "Modul " << module->GetName() << " berhasil didaftarkan." << std::endl;
        }
    }

    void AntiCheatClient::ReportDetection(const CheatDetection& detection)
    {
        // Log deteksi
        std::cout << "Cheat terdeteksi!" << std::endl;
        std::cout << "Tipe: " << static_cast<int>(detection.type) << std::endl;
        std::cout << "Detail: " << detection.details << std::endl;
        std::cout << "Proses: " << detection.processName << " (PID: " << detection.processId << ")" << std::endl;

        // Tampilkan pesan peringatan
        std::string message = "Garuda Hack Shield mendeteksi aktivitas mencurigakan!\n\n";
        message += "Detail: " + detection.details + "\n";
        message += "Proses: " + detection.processName + " (PID: " + std::to_string(detection.processId) + ")\n\n";
        message += "Game akan ditutup untuk keamanan.";

        MessageBoxA(NULL, message.c_str(), "Garuda Hack Shield - Peringatan!", MB_ICONWARNING);

        // Tutup game
        ExitProcess(0);
    }
}