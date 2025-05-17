#include <cstring>
#include <string>
#include <vector>
#include <unistd.h>
#include <cstdlib>
#include <android/log.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <stdio.h>
#include <cerrno>
#include <cstdarg>
#include "zygisk.hpp"

#define LOG_TAG "FingerprintFPCExp"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN, LOG_TAG, __VA_ARGS__)

static const char *TARGET_PROCESS_NICE_NAME = "YOUR_TARGET_PROCESS_NICE_NAME_HERE"; // GANTI INI

static int (*original_open)(const char* pathname, int flags, ...) = nullptr;
static int (*original_open64)(const char* pathname, int flags, ...) = nullptr;
static bool hooks_applied_to_target_process = false;

// Definisi hooked_open_for_experiment dan hooked_open64_for_experiment tetap sama
// seperti di respons saya sebelumnya. Saya akan singkat di sini untuk fokus pada perubahan.
// ... (Salin definisi hooked_open_for_experiment dari respons sebelumnya) ...
// ... (Salin definisi hooked_open64_for_experiment dari respons sebelumnya) ...

// Fungsi hook untuk open (contoh singkat, pastikan Anda salin versi lengkapnya)
int hooked_open_for_experiment(const char* pathname, int flags, ...) {
    mode_t mode = 0;
    if ((flags & O_CREAT) == O_CREAT) {
        va_list args;
        va_start(args, flags);
        mode = (mode_t)va_arg(args, int);
        va_end(args);
    }
    LOGI("hooked_open: path='%s', flags=%#x", pathname ? pathname : "NULL", flags);
    if (pathname && strcmp(pathname, "/dev/goodix_fp") == 0) {
        LOGI(">>> Intercepted open for /dev/goodix_fp. Simulating presence by opening /dev/null.");
        int fd_dev_null = -1;
        if (original_open) {
             fd_dev_null = original_open("/dev/null", O_RDWR);
        } else {
            LOGE("original_open is NULL for /dev/goodix_fp!");
            errno = EFAULT; return -1;
        }
        LOGI("For /dev/goodix_fp, returning FD of /dev/null: %d", fd_dev_null);
        return fd_dev_null;
    }
    if (original_open) {
        if ((flags & O_CREAT) == O_CREAT) return original_open(pathname, flags, mode);
        return original_open(pathname, flags);
    }
    LOGE("original_open is NULL at end of hooked_open!");
    errno = EFAULT; return -1;
}

// Fungsi hook untuk open64 (contoh singkat, pastikan Anda salin versi lengkapnya)
int hooked_open64_for_experiment(const char* pathname, int flags, ...) {
    mode_t mode = 0;
    if ((flags & O_CREAT) == O_CREAT) {
        va_list args;
        va_start(args, flags);
        mode = (mode_t)va_arg(args, int);
        va_end(args);
    }
    LOGI("hooked_open64: path='%s', flags=%#x", pathname ? pathname : "NULL", flags);
    if (pathname && strcmp(pathname, "/dev/goodix_fp") == 0) {
        LOGI(">>> Intercepted open64 for /dev/goodix_fp. Simulating presence by opening /dev/null.");
        int fd_dev_null = -1;
        if (original_open64) {
             fd_dev_null = original_open64("/dev/null", O_RDWR);
        } else if (original_open) {
             LOGW("original_open64 is NULL, falling back to original_open for /dev/goodix_fp via /dev/null");
             fd_dev_null = original_open("/dev/null", O_RDWR);
        } else {
            LOGE("original_open64 and original_open are NULL for /dev/goodix_fp!");
            errno = EFAULT; return -1;
        }
        LOGI("For /dev/goodix_fp, returning FD of /dev/null (via open64 hook): %d", fd_dev_null);
        return fd_dev_null;
    }
    if (original_open64) {
        if ((flags & O_CREAT) == O_CREAT) return original_open64(pathname, flags, mode);
        return original_open64(pathname, flags);
    } else if (original_open) {
        LOGW("original_open64 is NULL, falling back to original_open in hooked_open64");
         if ((flags & O_CREAT) == O_CREAT) return original_open(pathname, flags, mode);
        return original_open(pathname, flags);
    }
    LOGE("original_open64 and original_open are NULL at end of hooked_open64!");
    errno = EFAULT; return -1;
}


class FPCGoodixExperimentZygiskModule : public zygisk::ModuleBase {
public:
    void onLoad(zygisk::Api* api, JNIEnv* env) override {
        this->api = api;
        this->env = env;
        LOGI("FPCGoodixExperimentZygiskModule Zygisk module loaded (onLoad). Version 1.1");
    }

    void postAppSpecialize(const zygisk::AppSpecializeArgs* args) override {
        if (hooks_applied_for_target_process || !args || !args->nice_name) {
            return;
        }

        const char* raw_process_nice_name = env->GetStringUTFChars(args->nice_name, nullptr);
        if (!raw_process_nice_name) {
            return;
        }
        std::string current_process_nice_name_str = raw_process_nice_name;
        env->ReleaseStringUTFChars(args->nice_name, raw_process_nice_name);

        if (current_process_nice_name_str == TARGET_PROCESS_NICE_NAME) {
            LOGI(">>> Target process '%s' (UID: %d) detected. Applying PLT hooks to libc.so.",
                 current_process_nice_name_str.c_str(), args->uid);
            
            // Asumsikan pltHookRegister mengembalikan void dan menerima 4 argumen
            // Jika zygisk.hpp Anda berbeda, sesuaikan ini.
            api->pltHookRegister(
                "libc.so",
                "open",
                (void*)hooked_open_for_experiment,
                (void**)&original_open
            );
            api->pltHookRegister(
                "libc.so",
                "open64",
                (void*)hooked_open64_for_experiment,
                (void**)&original_open64
            );
            
            // Tidak ada cara langsung untuk memeriksa keberhasilan pltHookRegister jika return type-nya void.
            // Kita hanya bisa berharap ia berhasil jika tidak crash.
            LOGI("Attempted to register PLT hooks for open & open64 in libc.so for '%s'", current_process_nice_name_str.c_str());
            
            if (api->pltHookCommit()) { // pltHookCommit biasanya mengembalikan bool
                LOGI("PLT hooks committed successfully for '%s'.", current_process_nice_name_str.c_str());
                hooks_applied_for_target_process = true;
            } else {
                LOGE("Failed to commit PLT hooks for '%s'.", current_process_nice_name_str.c_str());
                // Jika commit gagal, hook mungkin tidak aktif.
                // Kosongkan pointer fungsi asli untuk mencegah panggilan ke alamat yang salah.
                original_open = nullptr;
                original_open64 = nullptr;
            }
        }
    }

    void preServerSpecialize(zygisk::ServerSpecializeArgs* args) override {
        // LOGI("preServerSpecialize called. UID: %d. System server UID: %d", getuid(), args->uid);
        // Kita fokus pada postAppSpecialize untuk menargetkan proses HAL
    }

private:
    zygisk::Api* api = nullptr;
    JNIEnv* env = nullptr;
};

REGISTER_ZYGISK_MODULE(FPCGoodixExperimentZygiskModule)