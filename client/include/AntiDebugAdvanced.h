#pragma once

namespace GarudaHS {
    class AntiDebugAdvanced {
    public:
        // dipanggil sekali waktu di Initialize
        static void Initialize();
        // dipanggil tiap Tick() atau sekali saja
        static void Tick();
    };
}