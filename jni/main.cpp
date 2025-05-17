#include <cstring>
#include <string>
#include <vector>
#include <unistd.h>    // Untuk ssize_t, readlink, dll.
#include <cstdlib>
#include <android/log.h>
#include <fcntl.h>     // Untuk O_RDWR, O_CREAT, dll.
#include <sys/stat.h>  // Tidak langsung digunakan, tapi terkait
#include <stdio.h>     // Untuk fopen, fgets, fclose
#include <cerrno>      // Untuk errno dan EACCES, EFAULT
#include <cstdarg>     // Untuk va_list, va_start, va_arg, va_end
#include "zygisk.hpp"  // Header Zygisk Anda (pastikan path-nya benar)

#define LOG_TAG "FingerprintFPCExp" // TAG untuk logging, bisa disesuaikan
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN, LOG_TAG, __VA_ARGS__)

// --- Konfigurasi Target ---
// PENTING: Ganti ini dengan nama proses yang benar yang menjalankan service HAL fingerprint utama Anda.
// Ini adalah nama yang akan muncul di args->nice_name saat postAppSpecialize dipanggil untuk proses tersebut.
// Contoh dari log Anda sebelumnya: "/vendor/bin/hw/android.hardware.biometrics.fingerprint@2.1-service"
// Namun, nice_name di Zygisk mungkin hanya nama service atau bagian dari path.
// Anda HARUS memverifikasi ini dengan mencatat args->nice_name untuk semua proses terlebih dahulu.
static const char *TARGET_PROCESS_NICE_NAME = "YOUR_TARGET_PROCESS_NICE_NAME_HERE"; // CONTOH: "android.hardware.biometrics.fingerprint@2.1-service"

// Variabel untuk menyimpan pointer ke fungsi asli
static int (*original_open)(const char* pathname, int flags, ...) = nullptr;
static int (*original_open64)(const char* pathname, int flags, ...) = nullptr;

// Flag untuk memastikan hook hanya dipasang sekali per proses target
static bool hooks_applied_for_target_process = false;

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


class FPCGoodixExperimentZygiskModule : public zygisk::ModuleBase {
public:
    void onLoad(zygisk::Api* api, JNIEnv* env) override {
        this->api = api;
        this->env = env;
        LOGI("FPCGoodixExperimentZygiskModule Zygisk module loaded (onLoad). Version 1.0");
    }

    // Dipanggil untuk setiap proses aplikasi yang di-fork oleh Zygote
    void postAppSpecialize(const zygisk::AppSpecializeArgs* args) override {
        if (hooks_applied_for_target_process) { // Jika hook sudah dipasang untuk proses target, jangan lakukan lagi
            return;
        }
        if (!args || !args->nice_name) {
            // LOGW("postAppSpecialize: args or nice_name is null. Skipping hook attempt.");
            return;
        }

        const char* raw_process_nice_name = env->GetStringUTFChars(args->nice_name, nullptr);
        if (!raw_process_nice_name) {
            // LOGW("postAppSpecialize: Failed to get nice_name chars. Skipping hook attempt.");
            return;
        }
        std::string current_process_nice_name_str = raw_process_nice_name;
        env->ReleaseStringUTFChars(args->nice_name, raw_process_nice_name);

        // Log nama proses untuk membantu debugging target proses
        // Aktifkan log ini jika Anda perlu mencari tahu nama proses target yang benar
        // LOGI("postAppSpecialize: Checking process with nice_name: '%s', uid: %d",
        //      current_process_nice_name_str.c_str(), args->uid);

        // Cek apakah ini proses target kita
        if (current_process_nice_name_str == TARGET_PROCESS_NICE_NAME) {
            LOGI(">>> Target process '%s' (UID: %d) detected in postAppSpecialize. Applying PLT hooks to libc.so.",
                 current_process_nice_name_str.c_str(), args->uid);
            
            bool success_open = api->pltHookRegister(
                "libc.so",  // Target library (biasanya libc.so untuk fungsi open)
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
                    hooks_applied_for_target_process = true; // Tandai bahwa hook sudah diterapkan untuk target ini
                } else {
                    LOGE("Failed to commit PLT hooks for '%s'.", current_process_nice_name_str.c_str());
                }
            } else {
                LOGE("Failed to register PLT hooks for open/open64 in libc.so for '%s'", current_process_nice_name_str.c_str());
                if (!success_open) LOGE("  open hook registration failed.");
                if (!success_open64) LOGE("  open64 hook registration failed.");
            }
        }
    }

    // preServerSpecialize biasanya untuk system_server.
    // Jika service HAL Anda bukan system_server, hook di sini mungkin tidak relevan untuk target spesifik itu.
    void preServerSpecialize(zygisk::ServerSpecializeArgs* args) override {
        LOGI("preServerSpecialize called. UID: %d. System server UID: %d", getuid(), args->uid);
        // Jika TARGET_PROCESS_NICE_NAME Anda adalah "system_server", Anda bisa meletakkan logika hook di sini.
        // Namun, karena service HAL fingerprint biasanya proses native terpisah, kita fokus pada postAppSpecialize.
    }

private:
    zygisk::Api* api = nullptr;
    JNIEnv* env = nullptr;
};

REGISTER_ZYGISK_MODULE(FPCGoodixExperimentZygiskModule)
```

**Sebelum Menggunakan Kode Ini di Perangkat FPC Anda:**

1.  **SANGAT PENTING: Verifikasi dan Set `TARGET_PROCESS_NICE_NAME`**:
    * Nilai `"YOUR_TARGET_PROCESS_NICE_NAME_HERE"` **harus diganti**.
    * Untuk menemukan nama yang benar:
        * Buat versi modul Zygisk yang sangat sederhana yang di `postAppSpecialize` hanya mencatat `args->uid` dan `env->GetStringUTFChars(args->nice_name, nullptr)`.
        * Instal modul ini, reboot, lalu periksa log Zygisk Anda.
        * Sambil itu, dari shell ADB, jalankan `ps -A -o PID,NAME,CMDLINE | grep fingerprint` atau `ps -A -o PID,NAME,CMDLINE | grep goodix` untuk menemukan PID dan nama dari service HAL sidik jari yang berjalan (misalnya, PID 1388 dari log `fingerhal.txt` Anda).
        * Cocokkan PID tersebut dengan UID dan `nice_name` yang dicatat oleh modul Zygisk sederhana Anda untuk menemukan `nice_name` yang benar untuk service HAL tersebut. Kemungkinan besar itu adalah sesuatu seperti `"android.hardware.biometrics.fingerprint@2.1-service"` atau path binernya jika `nice_name` adalah itu.
    * **Jika Anda tidak yakin, jangan lanjutkan ke langkah berikutnya karena hook bisa salah target dan menyebabkan masalah.**

2.  **Pastikan `zygisk.hpp` Ada**: Kode ini mengandalkan `zygisk.hpp` dari template Zygisk Anda.

3.  **Build Modul**: Compile kode ini sebagai bagian dari modul Zygisk Anda.

4.  **Backup (Sangat Direkomendasikan)**: Meskipun ini eksperimen di perangkat Anda yang berfungsi, selalu ada risiko kecil. Backup data penting Anda.

5.  **Instal dan Aktifkan**: Instal modul Magisk yang berisi Zygisk library Anda, aktifkan di Magisk Manager, dan **reboot**.

6.  **Amati Logcat dengan Seksama**:
    * Gunakan `adb logcat -s FingerprintFPCExp` untuk melihat output dari modul Anda.
    * Juga pantau log sistem umum untuk pesan dari `[GF_HAL]` (jika muncul), `FingerprintHal`, `fpCoreHal`, dan pesan terkait TEE (cari `TEEC_`, `Trustonic`, `Kinibi`, `tz`, `tee`, dll.).
    * Apakah Anda melihat log "Target process '...' detected..."?
    * Apakah Anda melihat log "Intercepted open for /dev/goodix\_fp..."?
    * **Log error baru apa yang muncul dari `[GF_HAL]` atau service HAL utama setelah itu?** Apakah ia mencoba operasi TEE? Apakah ada error TEE yang muncul (seperti `TEEC_ERROR_ITEM_NOT_FOUND` atau lainnya)?
    * Apakah fingerprint FPC Anda berhenti berfungsi (kemungkinan besar iya)?
    * Apakah sistem tetap beralih ke HAL FPC, atau apakah ia "nyangkut" dalam kondisi error karena upaya Goodix tidak langsung gagal di pemeriksaan device node awal?

Ini adalah eksperimen yang lebih aman daripada hook global dengan `xhook`. Semoga berhasil, dan berhati-hatilah. Laporkan kembali temuan An