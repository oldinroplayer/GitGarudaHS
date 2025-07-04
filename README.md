# Garuda Hack Shield (GarudaHS)

## Pengantar

Garuda Hack Shield (GarudaHS) adalah sistem anti-cheat komprehensif yang dirancang khusus untuk game Ragnarok Online. Sistem ini berfokus pada deteksi dan pencegahan berbagai jenis cheat yang umum digunakan dalam game Ragnarok Online, seperti CheatEngine, OpenKore, WPE (Winsock Packet Editor), RPE (Ragnarok Packet Editor), dan sejenisnya.

### Tujuan Utama

1. **Melindungi Integritas Game**: Mencegah pemain curang merusak pengalaman bermain bagi pemain lain
2. **Deteksi Proaktif**: Mendeteksi cheat sebelum dapat merusak ekonomi game atau keseimbangan permainan
3. **Pencegahan Efektif**: Mencegah penggunaan cheat dengan berbagai lapisan perlindungan
4. **Validasi Berkelanjutan**: Memastikan integritas klien game secara terus-menerus
5. **Pengalaman Bermain yang Adil**: Menciptakan lingkungan bermain yang adil bagi semua pemain

### Fitur Utama

- Deteksi proses dan thread mencurigakan
- Pemindaian overlay dan ESP hack
- Perlindungan anti-debugging
- Deteksi injeksi DLL
- Validasi tanda tangan digital
- Pemindaian signature di memori
- Deteksi thread yang dibajak
- Pemindaian hook IAT
- Sistem identifikasi hardware (HWID)
- Pemeriksaan integritas file
- Validasi sisi server

## Arsitektur Sistem

GarudaHS menggunakan arsitektur modular yang memungkinkan setiap komponen anti-cheat berfungsi secara independen namun terintegrasi. Sistem ini terdiri dari dua komponen utama:

1. **Komponen Klien (DLL)**: Diinjeksi ke dalam proses game dan melakukan pemeriksaan anti-cheat secara lokal
2. **Komponen Server**: Memvalidasi data yang dikirim dari klien dan menyimpan informasi tentang pemain yang terdeteksi menggunakan cheat

Arsitektur modular memungkinkan:
- Penambahan modul baru tanpa mengubah kode yang ada
- Pembaruan individual modul tanpa mempengaruhi seluruh sistem
- Konfigurasi yang fleksibel berdasarkan kebutuhan spesifik

## Struktur Folder

```
GarudaHS/
├── client/
│   ├── include/
│   │   ├── AntiDebug.h
│   │   ├── AntiSuspendThread.h
│   │   ├── DigitalSignatureValidator.h
│   │   ├── FileIntegrityCheck.h
│   │   ├── GarudaHS.h
│   │   ├── HijackedThreadDetector.h
│   │   ├── HWIDSystem.h
│   │   ├── IATHookScanner.h
│   │   ├── InjectionScanner.h
│   │   ├── MemorySignatureScanner.h
│   │   ├── OverlayScanner.h
│   │   ├── ProcessWatcher.h
│   │   └── ServerSideValidation.h
│   └── src/
│       ├── AntiCheatClient.cpp
│       ├── AntiDebug.cpp
│       ├── AntiSuspendThread.cpp
│       ├── DigitalSignatureValidator.cpp
│       ├── dllmain.cpp
│       ├── FileIntegrityCheck.cpp
│       ├── HijackedThreadDetector.cpp
│       ├── HWIDSystem.cpp
│       ├── IATHookScanner.cpp
│       ├── InjectionScanner.cpp
│       ├── MemorySignatureScanner.cpp
│       ├── OverlayScanner.cpp
│       ├── ProcessWatcher.cpp
│       └── ServerSideValidation.cpp
└── server/
    ├── include/
    │   └── GarudaHSServer.h
    └── src/
        └── server.cpp
```

## Cara Membuat Proyek Visual Studio 2022

### Membuat Proyek Client (DLL)

1. Buka Visual Studio 2022
2. Pilih "Create a new project"
3. Cari dan pilih "Dynamic-Link Library (DLL)" dengan platform C++
4. Klik "Next"
5. Pada halaman "Configure your new project":
   - Project name: GarudaHS_Client
   - Location: Browse ke folder `C:\Users\Administrator\Documents\GarudaHS\client`
   - Solution name: GarudaHS
   - Centang "Place solution and project in the same directory"
   - Klik "Create"
6. Setelah proyek dibuat, kita perlu mengkonfigurasi proyek untuk menggunakan C++20 dan arsitektur x86:
   - Klik kanan pada proyek "GarudaHS_Client" di Solution Explorer
   - Pilih "Properties"
   - Pada "Configuration Properties" > "General":
     - Set "C++ Language Standard" ke "ISO C++20 Standard (/std:c++20)"
     - Set "Platform Toolset" ke "Visual Studio 2022 (v143)"
   - Pada "Configuration Manager" (klik dropdown di toolbar atas), ubah "Active solution platform" ke "x86"
   - Klik "OK" untuk menyimpan perubahan
7. Tambahkan file yang sudah dibuat ke proyek:
   - Klik kanan pada folder "Source Files" di Solution Explorer
   - Pilih "Add" > "Existing Item"
   - Browse ke folder `C:\Users\Administrator\Documents\GarudaHS\client\src`
   - Pilih semua file .cpp dan klik "Add"
   - Klik kanan pada folder "Header Files" di Solution Explorer
   - Pilih "Add" > "Existing Item"
   - Browse ke folder `C:\Users\Administrator\Documents\GarudaHS\client\include`
   - Pilih semua file .h dan klik "Add"
8. Tambahkan library yang diperlukan:
   - Klik kanan pada proyek "GarudaHS_Client" di Solution Explorer
   - Pilih "Properties"
   - Pada "Configuration Properties" > "Linker" > "Input":
     - Tambahkan "user32.lib" ke "Additional Dependencies"
   - Klik "OK" untuk menyimpan perubahan

### Membuat Proyek Server (Console Application)

1. Klik kanan pada Solution "GarudaHS" di Solution Explorer
2. Pilih "Add" > "New Project"
3. Cari dan pilih "Console App" dengan platform C++
4. Klik "Next"
5. Pada halaman "Configure your new project":
   - Project name: GarudaHS_Server
   - Location: Browse ke folder `C:\Users\Administrator\Documents\GarudaHS\server`
   - Klik "Create"
6. Setelah proyek dibuat, kita perlu mengkonfigurasi proyek untuk menggunakan C++20 dan arsitektur x86:
   - Klik kanan pada proyek "GarudaHS_Server" di Solution Explorer
   - Pilih "Properties"
   - Pada "Configuration Properties" > "General":
     - Set "C++ Language Standard" ke "ISO C++20 Standard (/std:c++20)"
     - Set "Platform Toolset" ke "Visual Studio 2022 (v143)"
   - Klik "OK" untuk menyimpan perubahan
7. Tambahkan file yang sudah dibuat ke proyek:
   - Klik kanan pada folder "Source Files" di Solution Explorer
   - Pilih "Add" > "Existing Item"
   - Browse ke folder `C:\Users\Administrator\Documents\GarudaHS\server\src`
   - Pilih semua file .cpp dan klik "Add"
   - Klik kanan pada folder "Header Files" di Solution Explorer
   - Pilih "Add" > "Existing Item"
   - Browse ke folder `C:\Users\Administrator\Documents\GarudaHS\server\include`
   - Pilih semua file .h dan klik "Add"
8. Tambahkan library yang diperlukan:
   - Klik kanan pada proyek "GarudaHS_Server" di Solution Explorer
   - Pilih "Properties"
   - Pada "Configuration Properties" > "Linker" > "Input":
     - Tambahkan "ws2_32.lib" ke "Additional Dependencies"
   - Klik "OK" untuk menyimpan perubahan

## Cara Menggunakan Stud_PE untuk Hook DLL ke EXE

1. Download Stud_PE dari link yang diberikan: [https://docs.herc.ws/client/dll-import](https://docs.herc.ws/client/dll-import)
2. Buka Stud_PE
3. Buka file RRO.exe (client Ragnarok) dengan Stud_PE
4. Pilih tab "Import"
5. Klik kanan dan pilih "Add Import"
6. Pada dialog yang muncul:
   - Pilih "GarudaHS_Client.dll" sebagai DLL
   - Pilih "Initialize" sebagai fungsi yang akan dipanggil
   - Klik "OK"
7. Simpan perubahan dengan klik "Save"

## Roadmap Fitur

1. ✅ Process & Thread Watcher
2. ✅ Overlay Scanner (deteksi ESP/cheat window)
3. ✅ Anti-Debug (IsDebuggerPresent, NtQuery...)
4. ✅ Anti-Suspend Threads
5. ✅ Injection Scanner (DLL injection detect)
6. ✅ Digital Signature Validator
7. ✅ Memory Signature Scanner
8. ✅ Hijacked Thread Detector
9. ✅ IAT Hook Scanner
10. ✅ HWID System (hashing CPU, disk, MAC)
11. ✅ File Integrity Check (SHA-256 validation)
12. ✅ Server-Side Validation

## Deskripsi Modul Anti-Cheat

### 1. Process & Thread Watcher
Modul ini memantau proses dan thread yang berjalan di sistem untuk mendeteksi aplikasi cheat yang dikenal. Modul ini menggunakan Windows API untuk mendapatkan daftar proses yang berjalan dan memeriksa apakah ada proses cheat yang dikenal.

### 2. Overlay Scanner
Modul ini mendeteksi window overlay yang sering digunakan oleh cheat ESP (Extra Sensory Perception). Modul ini memeriksa window yang tidak terlihat (invisible) atau transparan yang mungkin digunakan untuk menampilkan informasi cheat.

### 3. Anti-Debug
Modul ini mendeteksi upaya debugging pada aplikasi. Modul ini menggunakan berbagai teknik seperti IsDebuggerPresent, CheckRemoteDebuggerPresent, dan NtQueryInformationProcess untuk mendeteksi debugger.

### 4. Anti-Suspend Threads
Modul ini mencegah upaya untuk menghentikan sementara (suspend) thread aplikasi, yang sering digunakan oleh cheat untuk memanipulasi game.

### 5. Injection Scanner
Modul ini mendeteksi upaya injeksi DLL ke dalam proses aplikasi. Modul ini memeriksa modul yang dimuat ke dalam proses dan membandingkannya dengan daftar modul yang diizinkan.

### 6. Digital Signature Validator
Modul ini memvalidasi tanda tangan digital file untuk memastikan integritas file. Modul ini menggunakan Windows API untuk memverifikasi tanda tangan digital file EXE dan DLL.

### 7. Memory Signature Scanner
Modul ini memindai memori untuk pola byte yang dikenal sebagai signature cheat. Modul ini dapat mendeteksi cheat yang sudah diinjeksi ke dalam memori proses.

### 8. Hijacked Thread Detector
Modul ini mendeteksi thread yang telah dibajak oleh cheat. Modul ini memeriksa alamat awal thread dan memastikan bahwa thread berjalan dari alamat yang valid.

### 9. IAT Hook Scanner
Modul ini mendeteksi hook pada Import Address Table (IAT), yang sering digunakan oleh cheat untuk mengalihkan panggilan fungsi. Modul ini membandingkan alamat fungsi di IAT dengan alamat fungsi yang sebenarnya.

### 10. HWID System
**Tujuan**: Mengidentifikasi perangkat secara unik untuk mencegah sharing akun dan ban evasion.

**Fungsi**:
- Menghasilkan ID unik berdasarkan hardware komputer yang sulit dipalsukan
- Mencegah pemain yang diblokir membuat akun baru dengan perangkat yang sama
- Mendeteksi sharing akun antar perangkat yang berbeda
- Menyediakan identifikasi persisten untuk validasi sisi server

**Implementasi**:
- Mengumpulkan informasi dari berbagai komponen hardware:
  * CPU (ID prosesor, nama, kecepatan)
  * Disk (serial number, model, ukuran)
  * MAC address dari adapter jaringan
  * Motherboard (serial number, manufacturer)
  * BIOS (serial number, versi)
  * GPU (nama, driver version)
  * Sistem operasi (versi, build number)
- Menghitung hash SHA-256 dari informasi hardware untuk menghasilkan ID unik
- Mengenkripsi HWID dengan AES untuk penyimpanan yang aman
- Menyediakan fungsi untuk memverifikasi HWID yang disimpan

### 11. File Integrity Check
**Tujuan**: Memastikan file game tidak dimodifikasi oleh cheat atau tool lain.

**Fungsi**:
- Memeriksa integritas file game secara berkala
- Mendeteksi modifikasi pada file EXE, DLL, dan data game
- Memantau perubahan pada file-file penting
- Memberikan notifikasi ketika file dimodifikasi

**Implementasi**:
- Menghitung hash SHA-256 dari file dan membandingkannya dengan nilai yang diharapkan
- Memantau perubahan pada ukuran file, waktu modifikasi, dan atribut
- Mendukung pemantauan direktori dan pola file (*.dll, *.exe)
- Menyediakan callback untuk menangani file yang dimodifikasi
- Memperbarui informasi file secara berkala untuk mendeteksi perubahan

### 12. Server-Side Validation
**Tujuan**: Memvalidasi integritas klien dari sisi server untuk mencegah bypass anti-cheat lokal.

**Fungsi**:
- Mengirimkan data validasi ke server untuk verifikasi tambahan
- Menerima instruksi dari server untuk tindakan yang perlu dilakukan
- Mencegah manipulasi anti-cheat lokal
- Memungkinkan pemblokiran terpusat pemain yang curang

**Implementasi**:
- Mengumpulkan data validasi seperti:
  * HWID dari sistem
  * Versi klien game
  * Hasil pemindaian dari modul anti-cheat lain
  * Daftar cheat yang terdeteksi
  * Daftar file yang dimodifikasi
- Menggunakan komunikasi terenkripsi dengan server menggunakan WinHTTP
- Mendukung berbagai tindakan server seperti:
  * Peringatan kepada pemain
  * Pemblokiran akses ke game
  * Permintaan pembaruan klien
  * Pengiriman pesan ke pemain
- Melakukan validasi secara berkala dengan interval yang dapat dikonfigurasi

## Cara Menggunakan Library Tambahan

### CryptoPP
Untuk modul HWID System dan File Integrity Check, kita menggunakan library CryptoPP untuk fungsi kriptografi seperti hashing SHA-256 dan enkripsi AES.

1. Download CryptoPP dari [https://www.cryptopp.com/](https://www.cryptopp.com/)
2. Ekstrak ke folder library
3. Tambahkan path include dan library ke proyek Visual Studio:
   - Klik kanan pada proyek "GarudaHS_Client" di Solution Explorer
   - Pilih "Properties"
   - Pada "Configuration Properties" > "C/C++" > "General":
     - Tambahkan path ke folder include CryptoPP di "Additional Include Directories"
   - Pada "Configuration Properties" > "Linker" > "General":
     - Tambahkan path ke folder lib CryptoPP di "Additional Library Directories"
   - Pada "Configuration Properties" > "Linker" > "Input":
     - Tambahkan "cryptopp.lib" ke "Additional Dependencies"
   - Klik "OK" untuk menyimpan perubahan

### nlohmann/json
Untuk modul Server-Side Validation, kita menggunakan library nlohmann/json untuk parsing JSON.

1. Download nlohmann/json dari [https://github.com/nlohmann/json](https://github.com/nlohmann/json)
2. Tambahkan file header json.hpp ke folder include proyek
3. Tidak perlu library tambahan karena ini adalah header-only library

## Cara Penggunaan Modul

### Menggunakan HWID System

HWID System dapat digunakan untuk mengidentifikasi perangkat secara unik dan mencegah sharing akun:

```cpp
// Mendapatkan instance HWID System
auto& client = GarudaHS::AntiCheatClient::GetInstance();
auto hwidSystem = std::dynamic_pointer_cast<GarudaHS::HWIDSystem>(client.GetModuleByName("HWID System"));

if (hwidSystem)
{
    // Mendapatkan HWID
    std::string hwid = hwidSystem->GetHWID();
    std::cout << "HWID: " << hwid << std::endl;
    
    // Menyimpan HWID ke file
    hwidSystem->SaveHWIDToFile("hwid.dat");
    
    // Memuat dan memverifikasi HWID dari file
    if (hwidSystem->LoadHWIDFromFile("hwid.dat"))
    {
        std::cout << "HWID valid!" << std::endl;
    }
    else
    {
        std::cout << "HWID tidak valid!" << std::endl;
    }
    
    // Mendapatkan informasi hardware
    auto cpuInfo = hwidSystem->GetCPUInfo();
    auto diskInfo = hwidSystem->GetDiskInfo();
    auto macAddress = hwidSystem->GetMACAddress();
    
    // Menampilkan informasi CPU
    for (const auto& info : cpuInfo)
    {
        std::cout << info.name << ": " << info.value << std::endl;
    }
}
```

### Menggunakan File Integrity Check

File Integrity Check dapat digunakan untuk memantau integritas file game:

```cpp
// Mendapatkan instance File Integrity Check
auto& client = GarudaHS::AntiCheatClient::GetInstance();
auto fileIntegrityCheck = std::dynamic_pointer_cast<GarudaHS::FileIntegrityCheck>(client.GetModuleByName("File Integrity Check"));

if (fileIntegrityCheck)
{
    // Menambahkan file untuk dipantau
    fileIntegrityCheck->AddFileToMonitor(L"C:\\Game\\game.exe");
    
    // Menambahkan direktori untuk dipantau
    fileIntegrityCheck->AddDirectoryToMonitor(L"C:\\Game\\data", L"*.dat");
    
    // Menetapkan callback untuk file yang dimodifikasi
    fileIntegrityCheck->SetFileModifiedCallback([](const std::wstring& filePath) {
        std::wcout << L"File dimodifikasi: " << filePath << std::endl;
        // Lakukan tindakan yang sesuai
    });
    
    // Memeriksa apakah file telah dimodifikasi
    if (fileIntegrityCheck->IsFileModified(L"C:\\Game\\game.exe"))
    {
        std::cout << "File game.exe telah dimodifikasi!" << std::endl;
    }
    
    // Mendapatkan daftar file yang dipantau
    auto monitoredFiles = fileIntegrityCheck->GetMonitoredFiles();
    std::cout << "Jumlah file yang dipantau: " << monitoredFiles.size() << std::endl;
}
```

### Menggunakan Server-Side Validation

Server-Side Validation dapat digunakan untuk memvalidasi integritas klien dari sisi server:

```cpp
// Mendapatkan instance Server-Side Validation
auto& client = GarudaHS::AntiCheatClient::GetInstance();
auto serverValidation = std::dynamic_pointer_cast<GarudaHS::ServerSideValidation>(client.GetModuleByName("Server-Side Validation"));

if (serverValidation)
{
    // Mengatur URL server
    serverValidation->SetServerUrl("https://api.garudahs.com/validate");
    
    // Mengatur interval validasi (dalam detik)
    serverValidation->SetValidationInterval(300); // 5 menit
    
    // Mengatur game ID
    serverValidation->SetGameId("garuda-game-1");
    
    // Mengatur session ID
    serverValidation->SetSessionId(GenerateSessionId());
    
    // Mengatur client version
    serverValidation->SetClientVersion("1.0.0");
    
    // Menetapkan callback untuk status validasi
    serverValidation->SetValidationStatusCallback(
        [](GarudaHS::ValidationStatus status, const std::string& message) {
            if (status == GarudaHS::ValidationStatus::VALID)
            {
                std::cout << "Validasi berhasil: " << message << std::endl;
            }
            else if (status == GarudaHS::ValidationStatus::INVALID)
            {
                std::cout << "Validasi gagal: " << message << std::endl;
                // Tampilkan pesan error
                MessageBoxA(NULL, message.c_str(), "GarudaHS - Validasi Gagal", MB_ICONERROR);
            }
        }
    );
    
    // Menetapkan callback untuk tindakan server
    serverValidation->SetServerActionCallback(
        [](const std::string& actionType, const std::string& actionData) {
            if (actionType == "shutdown")
            {
                // Matikan aplikasi
                MessageBoxA(NULL, actionData.c_str(), "GarudaHS - Perintah Server", MB_ICONWARNING);
                ExitProcess(0);
            }
            else if (actionType == "message")
            {
                // Tampilkan pesan
                MessageBoxA(NULL, actionData.c_str(), "GarudaHS - Pesan Server", MB_ICONINFORMATION);
            }
        }
    );
    
    // Menambahkan data cheat yang terdeteksi
    serverValidation->AddDetectedCheat("CheatEngine");
    
    // Menambahkan data file yang dimodifikasi
    serverValidation->AddModifiedFile("C:\\Game\\data\\items.dat");
    
    // Melakukan validasi manual
    if (serverValidation->ValidateNow())
    {
        std::cout << "Validasi manual berhasil!" << std::endl;
    }
    else
    {
        std::cout << "Validasi manual gagal!" << std::endl;
    }
}
```

## Pengembangan Masa Depan

Berikut adalah beberapa ide untuk pengembangan GarudaHS di masa depan:

### 1. Kernel-Mode Driver
Mengimplementasikan driver kernel-mode untuk meningkatkan keamanan dan deteksi. Driver kernel-mode memiliki akses lebih tinggi ke sistem dan dapat mendeteksi cheat yang beroperasi di level kernel.

### 2. Machine Learning untuk Deteksi Cheat
Menggunakan machine learning untuk mendeteksi pola perilaku mencurigakan yang mungkin mengindikasikan penggunaan cheat. Ini dapat membantu mendeteksi cheat baru yang belum diketahui.

### 3. Virtualization-Based Security
Menggunakan teknologi virtualisasi untuk mengisolasi proses game dan mencegah akses tidak sah. Ini dapat mencegah cheat yang mencoba memanipulasi memori game.

### 4. Obfuscation dan Anti-Tampering
Menerapkan teknik obfuscation dan anti-tampering yang lebih canggih untuk melindungi kode anti-cheat dari reverse engineering dan modifikasi.

### 5. Behavioral Analysis
Menganalisis perilaku pemain untuk mendeteksi pola yang tidak wajar, seperti akurasi yang terlalu tinggi atau gerakan yang tidak mungkin dilakukan oleh manusia.

### 6. Network Traffic Analysis
Menganalisis lalu lintas jaringan untuk mendeteksi bot dan cheat yang memanipulasi paket jaringan.

### 7. Screenshot Verification
Mengambil screenshot secara acak dan mengirimkannya ke server untuk verifikasi visual. Ini dapat membantu mendeteksi cheat visual seperti wallhack.

### 8. Hardware Fingerprinting yang Lebih Canggih
Mengembangkan metode fingerprinting hardware yang lebih canggih untuk mencegah pemain yang diblokir membuat akun baru.

### 9. Integrasi dengan Anti-Cheat Pihak Ketiga
Mengintegrasikan GarudaHS dengan solusi anti-cheat pihak ketiga yang sudah mapan seperti EasyAntiCheat atau BattlEye untuk meningkatkan keamanan.

### 10. Cross-Platform Support
Mengembangkan dukungan untuk platform lain seperti macOS dan Linux untuk game yang mendukung platform tersebut.