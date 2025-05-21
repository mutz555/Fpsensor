#include <cstdlib>
#include <unistd.h> // Untuk getpid()
#include <fcntl.h>
#include <android/log.h>
#include <string>
#include <dlfcn.h> // Untuk definisi dlopen (meskipun xhook menanganinya)
#include <thread>
#include <vector>

// Sertakan header API Zygisk
#include "zygisk.hpp"

// Sertakan header xhook
#include "xhook.h" // Pastikan path ini benar sesuai struktur proyek Anda

#define LOG_TAG "MyZygiskDlopenHook"
#define ALOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define ALOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)
#define ALOGW(...) __android_log_print(ANDROID_LOG_WARN, LOG_TAG, __VA_ARGS__)
#define ALOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)

// --- Definisi Pointer untuk Menyimpan Fungsi Asli ---
// Tanda tangan dan pointer untuk dlopen asli
typedef void* (*t_dlopen_orig)(const char* filename, int flags);
static t_dlopen_orig original_dlopen_ptr = nullptr; 

// Tanda tangan dan pointer untuk android_dlopen_ext asli
typedef void* (*t_android_dlopen_ext_orig)(const char* filename, int flags, const void* extinfo /*android_dlextinfo*/);
static t_android_dlopen_ext_orig original_android_dlopen_ext_ptr = nullptr;

// Variabel global untuk melacak status hook
static bool dlopen_hooked = false;
static bool android_dlopen_ext_hooked = false;

// --- Fungsi Pengganti (Hook) ---
// Fungsi pengganti untuk dlopen
void* my_dlopen_replacement_zygisk(const char* filename, int flags) {
    char current_process_name[256] = {0};
    FILE* cmdline = fopen("/proc/self/cmdline", "r");
    if (cmdline) {
        fread(current_process_name, sizeof(current_process_name) -1, 1, cmdline);
        fclose(cmdline);
    }

    // Log semua panggilan dlopen, atau filter untuk yang menarik
    if (filename) {
        if (strstr(filename, "fingerprint") || strstr(filename, "goodix") || strstr(filename, "fpsensor")) {
            ALOGI("ZYGISK_DLOPEN_HOOK: Proses '%s' (PID: %d) mencoba memuat filename='%s', flags=%d",
                  current_process_name, getpid(), filename, flags);
        } else {
            // Log level debug untuk panggilan dlopen lainnya
            ALOGD("ZYGISK_DLOPEN_HOOK: Proses '%s' (PID: %d) dlopen: %s", current_process_name, getpid(), filename);
        }
    }

    if (original_dlopen_ptr) {
        ALOGD("ZYGISK_DLOPEN_HOOK: Memanggil dlopen asli untuk '%s'", filename ? filename : "null");
        void* result = original_dlopen_ptr(filename, flags);
        
        // Log hanya untuk library tertentu
        if (filename && (strstr(filename, "fingerprint") || strstr(filename, "goodix") || strstr(filename, "fpsensor"))) {
            ALOGI("ZYGISK_DLOPEN_HOOK: Panggilan asli dlopen mengembalikan %p untuk filename='%s'", result, filename);
        }
        return result;
    } else {
        ALOGE("ZYGISK_DLOPEN_HOOK: original_dlopen_ptr tidak diset untuk proses '%s'!", current_process_name);
        // Fallback jika hook gagal
        return dlopen(filename, flags); 
    }
}

// Fungsi pengganti untuk android_dlopen_ext
void* my_android_dlopen_ext_replacement_zygisk(const char* filename, int flags, const void* extinfo) {
    char current_process_name[256] = {0};
    FILE* cmdline = fopen("/proc/self/cmdline", "r");
    if (cmdline) {
        fread(current_process_name, sizeof(current_process_name) -1, 1, cmdline);
        fclose(cmdline);
    }

    if (filename) {
        if (strstr(filename, "fingerprint") || strstr(filename, "goodix") || strstr(filename, "fpsensor")) {
            ALOGI("ZYGISK_ADLOPEN_HOOK: Proses '%s' (PID: %d) mencoba memuat filename='%s', flags=%d, extinfo=%p",
                  current_process_name, getpid(), filename, flags, extinfo);
        } else {
            // Log level debug untuk panggilan android_dlopen_ext lainnya
            ALOGD("ZYGISK_ADLOPEN_HOOK: Proses '%s' (PID: %d) android_dlopen_ext: %s", 
                  current_process_name, getpid(), filename);
        }
    }

    if (original_android_dlopen_ext_ptr) {
        ALOGD("ZYGISK_ADLOPEN_HOOK: Memanggil android_dlopen_ext asli untuk '%s'", filename ? filename : "null");
        void* result = original_android_dlopen_ext_ptr(filename, flags, extinfo);
        
        // Log hanya untuk library tertentu
        if (filename && (strstr(filename, "fingerprint") || strstr(filename, "goodix") || strstr(filename, "fpsensor"))) {
            ALOGI("ZYGISK_ADLOPEN_HOOK: Panggilan asli android_dlopen_ext mengembalikan %p untuk filename='%s'", 
                  result, filename);
        }
        return result;
    } else {
        ALOGE("ZYGISK_ADLOPEN_HOOK: original_android_dlopen_ext_ptr tidak diset untuk proses '%s'!", current_process_name);
        // Fallback dengan dlsym
        typedef void* (*t_android_dlopen_ext_sys)(const char*, int, const void*);
        t_android_dlopen_ext_sys sys_android_dlopen_ext = (t_android_dlopen_ext_sys)dlsym(RTLD_NEXT, "android_dlopen_ext");
        if (sys_android_dlopen_ext) return sys_android_dlopen_ext(filename, flags, extinfo);
        return nullptr;
    }
}

// Fungsi untuk memeriksa apakah proses perlu di-hook
static bool should_hook_process(const std::string& process_name) {
    // Buat daftar proses yang perlu di-hook
    // Anda bisa mengubah daftar ini sesuai kebutuhan
    static const std::vector<std::string> target_processes = {
        "system_server",
        "com.android.systemui",
        "com.android.settings",
        "com.android.keyguard"
        // Tambahkan proses lain yang relevan dengan sidik jari
    };
    
    // Opsi 1: Hook semua proses (tidak disarankan untuk produksi)
    // return true; 
    
    // Opsi 2: Hook hanya proses target
    for (const auto& target : target_processes) {
        if (process_name.find(target) != std::string::npos) {
            return true;
        }
    }
    
    // Opsi 3: Hook proses yang berkaitan dengan sidik jari
    // Cek apakah nama proses mengandung kata kunci tertentu
    if (process_name.find("fingerprint") != std::string::npos ||
        process_name.find("biometric") != std::string::npos ||
        process_name.find("goodix") != std::string::npos ||
        process_name.find("fpsensor") != std::string::npos) {
        return true;
    }
    
    return false;
}

static void do_zygisk_hooking_for_process(const char* current_process_name_cstr) {
    std::string process_name(current_process_name_cstr);
    ALOGI("Memulai hook dlopen/android_dlopen_ext di proses: %s (PID: %d)", 
          process_name.c_str(), getpid());
    
    // Cek apakah proses ini perlu di-hook
    if (!should_hook_process(process_name)) {
        ALOGI("Melewati hook untuk proses: %s - tidak dalam daftar target", process_name.c_str());
        return;
    }

    // Aktifkan debug xhook untuk informasi lebih detail
    xhook_enable_debug(1);
    
    // ----- HOOK DLOPEN -----
    bool dlopen_hook_success = false;
    int status;
    
    // Coba hook di libdl.so
    ALOGI("Mencoba hook dlopen di libdl.so untuk proses: %s", process_name.c_str());
    status = xhook_register(".*libdl\\.so$", "dlopen", 
                           (void*)my_dlopen_replacement_zygisk, 
                           (void**)&original_dlopen_ptr);
    if (status == 0) {
        dlopen_hook_success = true;
        dlopen_hooked = true;
        ALOGI("Hook untuk dlopen berhasil didaftarkan di libdl.so, proses: %s", process_name.c_str());
    } else {
        ALOGW("Gagal mendaftarkan hook untuk dlopen di libdl.so, proses: %s. Status: %d", 
              process_name.c_str(), status);
        
        // Coba hook di linker
        ALOGI("Mencoba hook dlopen di linker untuk proses: %s", process_name.c_str());
        status = xhook_register(".*linker(64)?$", "dlopen", 
                               (void*)my_dlopen_replacement_zygisk, 
                               (void**)&original_dlopen_ptr);
        if (status == 0) {
            dlopen_hook_success = true;
            dlopen_hooked = true;
            ALOGI("Hook untuk dlopen berhasil didaftarkan di linker, proses: %s", process_name.c_str());
        } else {
            ALOGW("Gagal mendaftarkan hook untuk dlopen di linker, proses: %s. Status: %d", 
                  process_name.c_str(), status);
            
            // Coba hook di libc.so sebagai fallback
            ALOGI("Mencoba hook dlopen di libc.so untuk proses: %s", process_name.c_str());
            status = xhook_register(".*libc\\.so$", "dlopen", 
                                   (void*)my_dlopen_replacement_zygisk, 
                                   (void**)&original_dlopen_ptr);
            if (status == 0) {
                dlopen_hook_success = true;
                dlopen_hooked = true;
                ALOGI("Hook untuk dlopen berhasil didaftarkan di libc.so, proses: %s", process_name.c_str());
            } else {
                ALOGE("Gagal mendaftarkan hook untuk dlopen di libc.so, proses: %s. Status: %d", 
                      process_name.c_str(), status);
            }
        }
    }

    if (!dlopen_hook_success) {
        ALOGE("Semua upaya hook dlopen gagal untuk proses: %s", process_name.c_str());
    }

    // ----- HOOK ANDROID_DLOPEN_EXT -----
    bool adlopen_hook_success = false;
    
    // Coba hook di libdl.so
    ALOGI("Mencoba hook android_dlopen_ext di libdl.so untuk proses: %s", process_name.c_str());
    status = xhook_register(".*libdl\\.so$", "android_dlopen_ext", 
                           (void*)my_android_dlopen_ext_replacement_zygisk, 
                           (void**)&original_android_dlopen_ext_ptr);
    if (status == 0) {
        adlopen_hook_success = true;
        android_dlopen_ext_hooked = true;
        ALOGI("Hook untuk android_dlopen_ext berhasil didaftarkan di libdl.so, proses: %s", process_name.c_str());
    } else {
        ALOGW("Gagal mendaftarkan hook untuk android_dlopen_ext di libdl.so, proses: %s. Status: %d", 
              process_name.c_str(), status);
        
        // Coba hook di linker
        ALOGI("Mencoba hook android_dlopen_ext di linker untuk proses: %s", process_name.c_str());
        status = xhook_register(".*linker(64)?$", "android_dlopen_ext", 
                               (void*)my_android_dlopen_ext_replacement_zygisk, 
                               (void**)&original_android_dlopen_ext_ptr);
        if (status == 0) {
            adlopen_hook_success = true;
            android_dlopen_ext_hooked = true;
            ALOGI("Hook untuk android_dlopen_ext berhasil didaftarkan di linker, proses: %s", process_name.c_str());
        } else {
            ALOGE("Gagal mendaftarkan hook untuk android_dlopen_ext di linker, proses: %s. Status: %d", 
                  process_name.c_str(), status);
            
            // Bisa ditambahkan fallback ke libc.so jika diperlukan
        }
    }

    if (!adlopen_hook_success) {
        ALOGE("Semua upaya hook android_dlopen_ext gagal untuk proses: %s", process_name.c_str());
    }
    
    // ----- TERAPKAN HOOK -----
    ALOGI("Menerapkan hook dengan xhook_refresh untuk proses: %s", process_name.c_str());
    status = xhook_refresh(1);
    if (status == 0) {
        ALOGI("xhook_refresh berhasil diterapkan di proses: %s", process_name.c_str());
        
        // Verifikasi apakah setidaknya satu hook berhasil diterapkan
        if (!dlopen_hook_success && !adlopen_hook_success) {
            ALOGW("PERHATIAN: xhook_refresh berhasil tapi tidak ada hook yang berhasil didaftarkan "
                  "di proses: %s", process_name.c_str());
        } else {
            // Log untuk memverifikasi keberhasilan hook
            std::string hooked_functions;
            if (dlopen_hook_success) hooked_functions += "dlopen ";
            if (adlopen_hook_success) hooked_functions += "android_dlopen_ext ";
            ALOGI("Hook berhasil diterapkan untuk fungsi: %s di proses: %s", 
                  hooked_functions.c_str(), process_name.c_str());
        }
    } else {
        ALOGE("xhook_refresh gagal di proses: %s, status: %d", process_name.c_str(), status);
    }
    
    // Opsional: Nonaktifkan debug setelah selesai untuk mengurangi spam log
    // xhook_enable_debug(0);
    
    ALOGI("Proses hooking Zygisk selesai untuk: %s", process_name.c_str());
}

class MyZygiskDlopenHookModule : public zygisk::ModuleBase {
public:
    void onLoad(zygisk::Api *api, JNIEnv *env) override {
        this->api = api;
        this->env = env;
        ALOGI("MyZygiskDlopenHookModule onLoad. PID: %d", getpid());
    }

    void postAppSpecialize(const zygisk::AppSpecializeArgs *args) override {
        if (!args || !args->nice_name) {
            ALOGE("postAppSpecialize: nice_name adalah null!");
            return;
        }
        
        // Dapatkan nama proses
        const char *process_name_chars = env->GetStringUTFChars(args->nice_name, nullptr);
        if (process_name_chars) {
            std::string process_name_str(process_name_chars); 
            env->ReleaseStringUTFChars(args->nice_name, process_name_chars);
            
            ALOGI("postAppSpecialize: Memproses: %s (UID: %d)", process_name_str.c_str(), args->uid);
            
            // Lakukan hooking dalam thread terpisah untuk menghindari blocking proses utama
            std::thread hook_thread([process_name_str]() {
                do_zygisk_hooking_for_process(process_name_str.c_str());
            });
            hook_thread.detach();
        } else {
            ALOGE("postAppSpecialize: Gagal mendapatkan nama proses!");
        }
    }
    
    void postServerSpecialize(const zygisk::ServerSpecializeArgs *args) override {
        ALOGI("postServerSpecialize: Memproses system_server");
        
        // Lakukan hooking untuk system_server
        std::thread hook_thread([]() {
            do_zygisk_hooking_for_process("system_server");
        });
        hook_thread.detach();
    }

private:
    zygisk::Api *api = nullptr;
    JNIEnv *env = nullptr;
};

// Daftarkan modul Zygisk Anda
REGISTER_ZYGISK_MODULE(MyZygiskDlopenHookModule)