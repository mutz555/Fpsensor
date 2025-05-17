#include <cstring>
#include <string>
#include <vector>
#include <unistd.h>    // Untuk ssize_t, readlink, dll.
#include <cstdlib>
#include <android/log.h>
#include <fcntl.h>     // Untuk O_RDWR, O_CREAT, dll.
#include <sys/stat.h>  // Tidak langsung digunakan, tapi terkait
#include <stdio.h>     // Untuk fopen, fgets, fclose
#include <dlfcn.h>     // Tidak digunakan untuk hook, tapi bisa untuk debug
#include <cerrno>      // Untuk errno dan EACCES, EFAULT
#include "zygisk.hpp"  // Header Zygisk Anda

#define LOG_TAG "FingerprintFPCExperiment"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN, LOG_TAG, __VA_ARGS__)

// --- Konfigurasi Target ---
// Nama proses yang menjalankan service HAL fingerprint utama.
// Berdasarkan log Anda, PID 1388 (di perangkat FPC Anda) menjalankan [GF_HAL] dan kemudian
// beralih ke "fpsensor_fingerprint". Anda perlu mengonfirmasi nama proses pasti dari PID tersebut.
// Kemungkinan besar: "/vendor/bin/hw/android.hardware.biometrics.fingerprint@2.1-service"
// Atau bisa juga "system_server" jika beberapa logika awal terjadi di sana sebelum HAL di-spawn.
// Untuk Zygisk postAppSpecialize, kita akan menggunakan nice_name yang mungkin adalah nama service.
static const char *TARGET_PROCESS_NICE_NAME = "android.hardware.biometrics.fingerprint@2.1-service";
// Anda mungkin perlu juga memeriksa path biner absolut jika nice_name berbeda:
// static const char *TARGET_PROCESS_BINARY_PATH = "/vendor/bin/hw/android.hardware.biometrics.fingerprint@2.1-service";


// Variabel untuk menyimpan pointer ke fungsi asli
static int (*original_open)(const char* pathname, int flags, ...) = nullptr;
static int (*original_open64)(const char* pathname, int flags, ...) = nullptr;

// Flag untuk memastikan hook hanya dipasang sekali per proses target
static bool hooks_applied_to_target = false;

// Fungsi hook untuk open
int hooked_open_for_experiment(const char* pathname, int flags, ...) {
    mode_t mode = 0;
    // O_CREAT adalah salah satu flag yang membutuhkan argumen mode ketiga
    if ((flags & O_CREAT) == O_CREAT) {
        va_list args;
        va_start(args, flags);
        mode = (mode_t)va_arg(args, int); // mode_t sering di-pass sebagai int
        va_end(args);
    }

    // Logging akan dilakukan oleh Zygisk jika hook terpasang pada proses yang benar
    LOGI("hooked_open: path='%s', flags=%#x", pathname ? pathname : "NULL", flags);

    if (pathname && strcmp(pathname, "/dev/goodix_fp") == 0) {
        LOGI(">>> Intercepted open for /dev/goodix_fp. Simulating presence by opening /dev/null.");
        int fd_dev_null = -1;
        if (original_open) {
             // Buka /dev/null dengan flag yang diminta (kecuali O_CREAT, O_EXCL, dll yang tidak relevan untuk /dev/null)
             // Untuk kesederhanaan, kita buka dengan O_RDWR.
             fd_dev_null = original_open("/dev/null", O_RDWR);
        } else {
            LOGE("original_open is NULL when trying to open /dev/null for /dev/goodix_fp!");
            errno = EFAULT; // Pointer buruk
            return -1;
        }
        LOGI("For /dev/goodix_fp, returning FD of /dev/null: %d", fd_dev_null);
        return fd_dev_null;
    }

    // Panggil fungsi open asli untuk path lain
    if (original_open) {
        if ((flags & O_CREAT) == O_CREAT) {
            return original_open(pathname, flags, mode);
        } else {
            return original_open(pathname, flags);
        }
    }
    LOGE("original_open is NULL at end of hooked_open!");
    errno = EFAULT;
    return -1;
}

// Fungsi hook untuk open64
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
        } else if (original_open) { // Fallback jika original_open64 tidak ditemukan/dihook
             LOGW("original_open64 is NULL, falling back to original_open for /dev/goodix_fp via /dev/null");
             fd_dev_null = original_open("/dev/null", O_RDWR);
        } else {
            LOGE("original_open64 and original_open are NULL for /dev/goodix_fp!");
            errno = EFAULT;
            return -1;
        }
        LOGI("For /dev/goodix_fp, returning FD of /dev/null (via open64 hook): %d", fd_dev_null);
        return fd_dev_null;
    }

    // Panggil fungsi open64 asli untuk path lain
    if (original_open64) {
        if ((flags & O_CREAT) == O_CREAT) {
            return original_open64(pathname, flags, mode);
        } else {
            return original_open64(pathname, flags);
        }
    } else if (original_open) { // Fallback
        LOGW("original_open64 is NULL, falling back to original_open in hooked_open64");
         if ((flags & O_CREAT) == O_CREAT) {
            return original_open(pathname, flags, mode);
        } else {
            return original_open(pathname, flags);
        }
    }
    LOGE("original_open64 and original_open are NULL at end of hooked_open64!");
    errno = EFAULT;
    return -1;
}


class FPCGoodixExperimentModule : public zygisk::ModuleBase {
public:
    void onLoad(zygisk::Api* api, JNIEnv* env) override {
        this->api = api;
        this->env = env;
        LOGI("FPCGoodixExperimentModule Zygisk module loaded (onLoad).");
    }

    // Dipanggil untuk setiap proses aplikasi yang di-fork oleh Zygote
    void postAppSpecialize(const zygisk::AppSpecializeArgs* args) override {
        if (hooks_applied_to_target) { // Jika hook sudah dipasang untuk proses target, jangan lakukan lagi
            return;
        }
        if (!args || !args->nice_name) {
            LOGW("postAppSpecialize: args or nice_name is null.");
            return;
        }

        const char* raw_process_nice_name = env->GetStringUTFChars(args->nice_name, nullptr);
        if (!raw_process_nice_name) {
            LOGW("postAppSpecialize: Failed to get nice_name chars.");
            return;
        }
        std::string current_process_nice_name_str = raw_process_nice_name;
        env->ReleaseStringUTFChars(args->nice_name, raw_process_nice_name);

        // Log nama proses untuk debugging target
        // LOGI("postAppSpecialize: Checking process with nice_name: '%s', uid: %d",
        //      current_process_nice_name_str.c_str(), args->uid);

        // Cek apakah ini proses target kita
        // Nama service HAL native mungkin muncul sebagai nice_name jika di-spawn dengan cara tertentu.
        // Atau, jika service HAL adalah bagian dari system_server, Anda perlu menargetkan "system_server".
        // Untuk service native yang di-fork oleh init, penargetan dari Zygisk bisa lebih sulit.
        // Kita asumsikan TARGET_PROCESS_NICE_NAME adalah nama yang akan muncul di nice_name.
        if (current_process_nice_name_str == TARGET_PROCESS_NICE_NAME) {
            LOGI(">>> Target process '%s' detected in postAppSpecialize. Applying PLT hooks to libc.so.",
                 current_process_nice_name_str.c_str());
            
            bool success_open = api->pltHookRegister(
                "libc.so",  // Target library
                "open",     // Simbol yang di-hook
                (void*)hooked_open_for_experiment,
                (void**)&original_open
            );
            bool success_open64 = api->pltHookRegister(
                "libc.so",
                "open64",
                (void*)hooked_open64_for_experiment,
                (void**)&original_open64
            );
            
            if (success_open && success_open64) {
                LOGI("Registered PLT hooks for open & open64 in libc.so for '%s'", current_process_nice_name_str.c_str());
                if (api->pltHookCommit()) {
                    LOGI("PLT hooks committed successfully for '%s'.", current_process_nice_name_str.c_str());
                    hooks_applied_to_target = true; // Tandai bahwa hook sudah diterapkan untuk target ini
                } else {
                    LOGE("Failed to commit PLT hooks for '%s'.", current_process_nice_name_str.c_str());
                }
            } else {
                LOGE("Failed to register PLT hooks for open/open64 in libc.so for '%s' (open: %d, open64: %d)", 
                     current_process_nice_name_str.c_str(), success_open, success_open64);
            }
        }
    }

    // preServerSpecialize dipanggil sebelum system_server dispesialisasi.
    // Jika service HAL Anda adalah bagian dari system_server atau di-load dari sana,
    // ini bisa menjadi tempat untuk hook. Namun, service HAL native biasanya proses sendiri.
    void preServerSpecialize(zygisk::ServerSpecializeArgs* args) override {
        LOGI("preServerSpecialize called. Current UID: %d. Is system server: %d", getuid(), args->uid);
        // Jika TARGET_PROCESS_NICE_NAME adalah "system_server" dan Anda ingin hook di sana:
        // if (strcmp(TARGET_PROCESS_NICE_NAME, "system_server") == 0 && !hooks_applied_to_target) {
        //     LOGI("Target process 'system_server' detected in preServerSpecialize. Applying PLT hooks to libc.so.");
        //     // Logika hook yang sama seperti di postAppSpecialize
        // }
    }

private:
    zygisk::Api* api = nullptr;
    JNIEnv* env = nullptr;
};

REGISTER_ZYGISK_MODULE(FPCGoodixExperimentModule)
```

**Penjelasan dan Catatan Penting:**

1.  **`LOG_TAG`**: Diubah menjadi "FingerprintFPCExperiment" agar mudah difilter.
2.  **`TARGET_PROCESS_NICE_NAME`**:
    * Ini **sangat krusial**. Anda harus menggantinya dengan nama proses yang benar yang menjalankan service HAL sidik jari utama (`/vendor/bin/hw/android.hardware.biometrics.fingerprint@2.1-service`) sebagaimana nama itu muncul di `args->nice_name` saat `postAppSpecialize` dipanggil untuk proses tersebut.
    * **Cara Menemukannya**: Tambahkan log di `postAppSpecialize` untuk mencetak `current_process_nice_name_str` dari *semua* proses. Kemudian, saat Anda tahu PID dari service HAL Anda (misalnya 1388 dari logcat sebelumnya), cari di log Zygisk nama apa yang muncul untuk PID tersebut atau untuk service yang relevan. Service native yang di-fork oleh `init` mungkin tidak selalu melewati `postAppSpecialize` dengan `nice_name` yang mudah ditebak. Jika service HAL Anda tidak di-fork dari Zygote dengan cara ini, pendekatan Zygisk ini mungkin tidak akan meng-hooknya.
3.  **`hooks_applied_to_target`**: Flag boolean untuk memastikan kita hanya mencoba memasang hook sekali untuk proses target.
4.  **Hook di `postAppSpecialize`**:
    * Ini adalah tempat yang lebih baik untuk hook yang spesifik proses aplikasi atau service yang di-spawn seperti aplikasi.
    * Kita membandingkan `current_process_nice_name_str` dengan `TARGET_PROCESS_NICE_NAME`.
    * Jika cocok, kita menggunakan `api->pltHookRegister` untuk meng-hook `open` dan `open64` di `libc.so` yang dimuat oleh **proses target tersebut saja**. Ini jauh lebih aman daripada hook global.
5.  **Fungsi Hook (`hooked_open_for_experiment`, `hooked_open64_for_experiment`)**:
    * Mencatat path yang diminta.
    * Jika path adalah `"/dev/goodix_fp"`, ia akan mencatat ini, membuka `/dev/null` menggunakan fungsi asli (`original_open` atau `original_open64`), dan mengembalikan file descriptor dari `/dev/null`.
    * Untuk path lain, ia memanggil fungsi asli.
6.  **`preServerSpecialize`**: Saya biarkan kosong untuk logika hook utama karena service HAL fingerprint biasanya bukan `system_server` itu sendiri, melainkan proses native terpisah. Jika ternyata `system_server` yang melakukan panggilan `open` ke `/dev/goodix_fp` yang ingin Anda cegat, Anda bisa memindahkan logika hook ke sini dan menargetkan `system_server`.
7.  **Tidak Ada `get_current_process_name_fp()` di Dalam Fungsi Hook**: Karena hook sekarang dipasang secara spesifik untuk proses target, kita tidak perlu lagi memeriksa nama proses di dalam setiap panggilan `open`, yang menghilangkan potensi overhead dan bootloop dari sana.

**Langkah Menggunakan Kode Ini (di Perangkat FPC Anda):**

1.  **Identifikasi Nama Proses Target yang Benar**: Ini langkah pertama yang paling penting. Gunakan modul Zygisk yang hanya mencatat `args->nice_name` di `postAppSpecialize` untuk semua proses, lalu temukan nama yang sesuai untuk service HAL sidik jari Anda.
2.  **Sesuaikan `TARGET_PROCESS_NICE_NAME`** di kode di atas.
3.  **Build Modul Zygisk**.
4.  **Instal dan Aktifkan** di Magisk, lalu **Reboot**.
5.  **Amati Logcat dengan Cermat**:
    * Filter dengan TAG `FingerprintFPCExperiment`.
    * Apakah Anda melihat log "Target process '...' detected..."?
    * Apakah Anda melihat log "Registered PLT hooks..." dan "PLT hooks committed successfully..."?
    * Ketika Anda mencoba menggunakan sidik jari (yang seharusnya memicu logika trial-and-error HAL), apakah Anda melihat log "Intercepted open for /dev/goodix\_fp..."?
    * **Log apa yang muncul dari `[GF_HAL]` (jika ada) atau service HAL utama setelah itu?** Apakah ia mencoba operasi TEE? Apakah ada error baru?
    * Apakah fingerprint FPC Anda berhenti berfungsi (kemungkinan besar iya)?

Ini adalah eksperimen yang lebih aman dan lebih terarah daripada hook global. Semoga berhas