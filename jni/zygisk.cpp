#include "zygisk.hpp"

namespace zygisk {
    static ModuleBase *g_module = nullptr;

    void registerModule(ModuleBase *module) {
        g_module = module;
    }

    // Kalau kamu butuh akses ke module dari luar
    ModuleBase* getRegisteredModule() {
        return g_module;
    }
}