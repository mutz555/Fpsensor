#include <cstring>
#include <string>
#include <vector>
#include <unistd.h>
#include <cstdlib>
#include <android/log.h>
#include <fcntl.h>
#include <sys/stat.h>  // Untuk struct stat dan fungsi stat()
#include <stdio.h>
#include <cerrno>
#include <cstdarg>
#include "zygisk.hpp"  // Header Zygisk Anda

#define LOG_TAG "FingerprintFPCExp"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN, LOG_TAG, __VA_ARGS__)

static const char *TARGET_PROCESS_NICE_NAME = "YOUR_TARGET_PROCESS_NICE_NAME_HERE"; // GANTI INI

static int (*original_open)(const char* pathname, int flags, ...) = nullptr;
static int (*original_open64)(const char* pathname, int flags, ...) = nullptr;
static bool hooks_applied_to_target_process = false;

// Definisi hooked_open_for_experiment dan hooked_open64_for_experiment
// tetap sama seperti di respons saya sebelumnya. Saya akan singkat di sini.
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


// Fungsi untuk mendapatkan dev_t dan ino_t dari library yang dimuat
// Ini adalah pendekatan sederhana, mungkin perlu disesuaikan berdasarkan bagaimana path library ditemukan
bool get_library_stat(const char* lib_name_suffix, dev_t* dev, ino_t* ino) {
    char line[1024];
    FILE* fp = fopen("/proc/self/maps", "r");
    if (!fp) {
        LOGE("Failed to open /proc/self/maps");
        return false;
    }

    std::string lib_suffix_str = lib_name_suffix;
    bool found = false;

    while (fgets(line, sizeof(line), fp)) {
        // Format baris maps: address perms offset dev inode pathname
        char path[256] = {0};
        // Mencari baris yang mengandung path library dan bisa dieksekusi (perms r-xp)
        // Ini adalah heuristik, mungkin tidak selalu akurat 100% untuk path libc.so yang benar
        if (strstr(line, " r-xp ") && strstr(line, lib_name_suffix)) {
             // Ambil path dari baris maps
            // Contoh baris: 7b2f000000-7b2f0a1000 r-xp 00000000 103:0c 12345   /apex/com.android.runtime/lib64/bionic/libc.so
            char* pathname_start = strstr(line, "/"); // Cari '/' pertama untuk path
            if (pathname_start) {
                // Hapus spasi di awal path jika ada
                while(*pathname_start == ' ' && *pathname_start != '\0') pathname_start++;
                // Hapus newline di akhir
                char* newline = strchr(pathname_start, '\n');
                if (newline) *newline = '\0';

                // Pastikan path yang ditemukan benar-benar berakhiran dengan lib_name_suffix
                // dan bukan hanya mengandungnya sebagai substring.
                std::string current_path_str = pathname_start;
                if (current_path_str.length() >= lib_suffix_str.length() &&
                    current_path_str.substr(current_path_str.length() - lib_suffix_str.length()) == lib_suffix_str) {

                    struct stat s;
                    if (stat(pathname_start, &s) == 0) {
                        *dev = s.st_dev;
                        *ino = s.st_ino;
                        LOGI("Found library %s: path=%s, dev=%ld, ino=%ld", lib_name_suffix, pathname_start, (long)s.st_dev, (long)s.st_ino);
                        found = true;
                        break;
                    } else {
                        LOGE("stat failed for %s: %s", pathname_start, strerror(errno));
                    }
                }
            }
        }
    }
    fclose(fp);
    if (!found) {
        LOGE("Library %s not found in /proc/self/maps or stat failed", lib_name_suffix);
    }
    return found;
}


class FPCGoodixExperimentZygiskModule : public zygisk::ModuleBase {
public:
    void onLoad(zygisk::Api* api, JNIEnv* env) override {
        this->api = api;
        this->env = env;
        LOGI("FPCGoodixExperimentZygiskModule Zygisk module loaded (onLoad). Version 1.2 (using dev/ino)");
    }

    void postAppSpecialize(const zygisk::AppSpecializeArgs* args) override {
        if (hooks_applied_to_target_process || !args || !args->nice_name) {
            return;
        }

        const char* raw_process_nice_name = env->GetStringUTFChars(args->nice_name, nullptr);
        if (!raw_process_nice_name) {
            return;
        }
        std::string current_process_nice_name_str = raw_process_nice_name;
        env->ReleaseStringUTFChars(args->nice_name, raw_process_nice_name);

        if (current_process_nice_name_str == TARGET_PROCESS_NICE_NAME) {
            LOGI(">>> Target process '%s' (UID: %d) detected. Applying PLT hooks.",
                 current_process_nice_name_str.c_str(), args->uid);
            
            dev_t libc_dev;
            ino_t libc_ino;

            // Path libc.so bisa bervariasi (APEX vs non-APEX)
            // Kita coba beberapa path umum atau suffix
            // Cara paling robust adalah dengan membaca /proc/self/maps
            // atau menggunakan dl_iterate_phdr, tapi itu lebih kompleks.
            // Untuk kesederhanaan, kita akan coba mencari suffix "libc.so"
            if (get_library_stat("libc.so", &libc_dev, &libc_ino)) {
                LOGI("Using dev/ino for libc.so: dev=%ld, ino=%ld", (long)libc_dev, (long)libc_ino);

                api->pltHookRegister(
                    libc_dev, libc_ino, "open",
                    (void*)hooked_open_for_experiment, (void**)&original_open
                );
                api->pltHookRegister(
                    libc_dev, libc_ino, "open64",
                    (void*)hooked_open64_for_experiment, (void**)&original_open64
                );
                
                LOGI("Registered PLT hooks for open & open64 in identified libc.so for '%s'", current_process_nice_name_str.c_str());
                
                if (api->pltHookCommit()) {
                    LOGI("PLT hooks committed successfully for '%s'.", current_process_nice_name_str.c_str());
                    hooks_applied_to_target_process = true;
                } else {
                    LOGE("Failed to commit PLT hooks for '%s'.", current_process_nice_name_str.c_str());
                    original_open = nullptr;
                    original_open64 = nullptr;
                }
            } else {
                LOGE("Could not get stat for libc.so. Hooks not applied for %s.", current_process_nice_name_str.c_str());
            }
        }
    }

    void preServerSpecialize(zygisk::ServerSpecializeArgs* args) override {
        // LOGI("preServerSpecialize called. UID: %d. System server UID: %d", getuid(), args->uid);
    }

private:
    zygisk::Api* api = nullptr;
    JNIEnv* env = nullptr;
};

REGISTER_ZYGISK_MODULE(FPCGoodixExperimentZygiskModule)