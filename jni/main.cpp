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

// --- Definisi Pointer untuk Menyimpan Fungsi Asli ---
// Tanda tangan dan pointer untuk dlopen asli
typedef void* (*t_dlopen_orig)(const char* filename, int flags);
static t_dlopen_orig original_dlopen_ptr = nullptr; 

// Tanda tangan dan pointer untuk android_dlopen_ext asli
typedef void* (*t_android_dlopen_ext_orig)(const char* filename, int flags, const void* extinfo /*android_dlextinfo*/);
static t_android_dlopen_ext_orig original_android_dlopen_ext_ptr = nullptr;


// --- Fungsi Pengganti (Hook) ---
// Fungsi pengganti untuk dlopen
void* my_dlopen_replacement_zygisk(const char* filename, int flags) {
    char current_process_name[256] = {0};
    FILE* cmdline = fopen("/proc/self/cmdline", "r");
    if (cmdline) {
        fread(current_process_name, sizeof(current_process_name) -1, 1, cmdline);
        fclose(cmdline);
    }

    // Log semua panggilan dlopen, atau filter untuk yang menarik (misalnya, mengandung "fingerprint", "goodix", "fpsensor")
    if (filename && (strstr(filename, "fingerprint") || strstr(filename, "goodix") || strstr(filename, "fpsensor"))) {
        ALOGI("ZYGISK_DLOPEN_HOOK: Proses '%s' (PID: %d) mencoba memuat filename='%s', flags=%d",
              current_process_name, getpid(), filename, flags);
    } else if (filename) {
        // Untuk debugging awal, mungkin log semua panggilan dlopen dari proses sistem penting
        // if (strstr(current_process_name, "system_server") || strstr(current_process_name, "android.settings")) {
        //     ALOGI("ZYGISK_DLOPEN_HOOK: Proses '%s' (PID: %d) dlopen: %s", current_process_name, getpid(), filename);
        // }
    }


    if (original_dlopen_ptr) {
        void* result = original_dlopen_ptr(filename, flags);
        // Jika Anda ingin log hasilnya juga:
        // if (filename && (strstr(filename, "fingerprint") || strstr(filename, "goodix") || strstr(filename, "fpsensor"))) {
        //     ALOGI("ZYGISK_DLOPEN_HOOK: Panggilan asli dlopen mengembalikan %p untuk filename='%s'", result, filename);
        // }
        return result;
    } else {
        ALOGE("ZYGISK_DLOPEN_HOOK: original_dlopen_ptr tidak diset untuk proses '%s'!", current_process_name);
        // Fallback jika hook gagal tetapi kita tidak ingin crash (meskipun ini seharusnya tidak terjadi jika xhook bekerja)
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

    if (filename && (strstr(filename, "fingerprint") || strstr(filename, "goodix") || strstr(filename, "fpsensor"))) {
        ALOGI("ZYGISK_ADLOPEN_HOOK: Proses '%s' (PID: %d) mencoba memuat filename='%s', flags=%d, extinfo=%p",
              current_process_name, getpid(), filename, flags, extinfo);
    }

    if (original_android_dlopen_ext_ptr) {
        void* result = original_android_dlopen_ext_ptr(filename, flags, extinfo);
        // if (filename && (strstr(filename, "fingerprint") || strstr(filename, "goodix") || strstr(filename, "fpsensor"))) {
        //     ALOGI("ZYGISK_ADLOPEN_HOOK: Panggilan asli android_dlopen_ext mengembalikan %p untuk filename='%s'", result, filename);
        // }
        return result;
    } else {
        ALOGE("ZYGISK_ADLOPEN_HOOK: original_android_dlopen_ext_ptr tidak diset untuk proses '%s'!", current_process_name);
        // Fallback
        typedef void* (*t_android_dlopen_ext_sys)(const char*, int, const void*);
        t_android_dlopen_ext_sys sys_android_dlopen_ext = (t_android_dlopen_ext_sys)dlsym(RTLD_NEXT, "android_dlopen_ext");
        if (sys_android_dlopen_ext) return sys_android_dlopen_ext(filename, flags, extinfo);
        return nullptr;
    }
}


static void do_zygisk_hooking_for_process(const char* current_process_name_cstr) {
    ALOGI("Memulai hook dlopen/android_dlopen_ext di proses Zygote-spawned: %s", current_process_name_cstr);

    // xhook_enable_debug(1); // Aktifkan jika perlu debug xhook

    // Hook dlopen
    // Target utama adalah libdl.so atau linker
    // Regex ".*\\libdl.so$" atau ".*\\linker.*$"
    // Beberapa implementasi mungkin memiliki dlopen di libc.so juga
    int dlopen_reg_status = xhook_register(".*\\libdl.so$", "dlopen", (void*)my_dlopen_replacement_zygisk, (void**)&original_dlopen_ptr);
    if (dlopen_reg_status != 0) {
         dlopen_reg_status = xhook_register(".*\\linker(64)?$", "dlopen", (void*)my_dlopen_replacement_zygisk, (void**)&original_dlopen_ptr);
    }
     if (dlopen_reg_status != 0) {
         dlopen_reg_status = xhook_register(".*\\libc.so$", "dlopen", (void*)my_dlopen_replacement_zygisk, (void**)&original_dlopen_ptr);
    }

    if (dlopen_reg_status != 0) {
        ALOGE("Gagal mendaftarkan hook untuk dlopen di proses: %s. Status: %d", current_process_name_cstr, dlopen_reg_status);
    } else {
        ALOGI("Hook untuk dlopen berhasil didaftarkan di proses: %s", current_process_name_cstr);
    }

    // Hook android_dlopen_ext
    int adlopen_reg_status = xhook_register(".*\\libdl.so$", "android_dlopen_ext", (void*)my_android_dlopen_ext_replacement_zygisk, (void**)&original_android_dlopen_ext_ptr);
    if (adlopen_reg_status != 0) {
        adlopen_reg_status = xhook_register(".*\\linker(64)?$", "android_dlopen_ext", (void*)my_android_dlopen_ext_replacement_zygisk, (void**)&original_android_dlopen_ext_ptr);
    }

    if (adlopen_reg_status != 0) {
        ALOGE("Gagal mendaftarkan hook untuk android_dlopen_ext di proses: %s. Status: %d", current_process_name_cstr, adlopen_reg_status);
    } else {
        ALOGI("Hook untuk android_dlopen_ext berhasil didaftarkan di proses: %s", current_process_name_cstr);
    }
    
    if (xhook_refresh(1) != 0) { // Terapkan hook untuk proses saat ini
        ALOGE("xhook_refresh gagal di proses: %s", current_process_name_cstr);
    } else {
        ALOGI("xhook_refresh berhasil diterapkan di proses: %s", current_process_name_cstr);
    }
    ALOGI("Proses hooking Zygisk selesai untuk: %s", current_process_name_cstr);
}


class MyZygiskDlopenHookModule : public zygisk::ModuleBase {
public:
    void onLoad(zygisk::Api *api, JNIEnv *env) override {
        this->api = api;
        this->env = env;
        ALOGI("MyZygiskDlopenHookModule onLoad. PID: %d", getpid());
    }

    void postAppSpecialize(const zygisk::AppSpecializeArgs *args) override {
        // Dapatkan nama proses
        const char *process_name_chars = env->GetStringUTFChars(args->nice_name, nullptr);
        if (process_name_chars) {
            std::string process_name_str(process_name_chars); 
            env->ReleaseStringUTFChars(args->nice_name, process_name_chars);

            // Kita bisa memfilter proses mana yang ingin di-hook.
            // Misalnya, hanya proses sistem atau aplikasi tertentu.
            // Untuk debugging awal, kita bisa mencoba pada beberapa proses sistem penting.
            // Contoh: "system_server", "com.android.settings"
            // Atau jika ingin lebih luas, perhatikan dampaknya pada performa.
            // if (process_name_str == "system_server" || process_name_str.rfind("com.android.settings", 0) == 0) {
                ALOGI("postAppSpecialize: Mencoba hook dlopen di proses: %s (UID: %d)", process_name_str.c_str(), args->uid);
                
                std::thread hook_thread([process_name_str]() {
                    do_zygisk_hooking_for_process(process_name_str.c_str());
                });
                hook_thread.detach();
            // }
        }
    }

private:
    zygisk::Api *api = nullptr;
    JNIEnv *env = nullptr;
};

// Daftarkan modul Zygisk Anda
REGISTER_ZYGISK_MODULE(MyZygiskDlopenHookModule)

