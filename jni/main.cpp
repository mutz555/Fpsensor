#include <cstdlib>
#include <unistd.h>
#include <fcntl.h>
#include <android/log.h>
#include <string>
#include <dlfcn.h> // Untuk definisi dlopen, dlsym (meskipun xhook menanganinya)
#include <thread>  // Untuk std::thread

// Sertakan header API Zygisk
#include "zygisk.hpp"

// Sertakan header xhook
#include "xhook.h" // Pastikan path ini benar sesuai struktur proyek Anda

#define LOG_TAG "MyFingerprintXHookLog" // Tag log
#define ALOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)
#define ALOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define ALOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

// Nama proses target
const char *TARGET_PROCESS_NAME = "android.hardware.biometrics.fingerprint@2.1-service";

// --- Definisi Fungsi Asli dan Pengganti untuk dlopen ---
// Tanda tangan untuk dlopen
typedef void* (*t_dlopen)(const char* filename, int flags);
t_dlopen original_dlopen = nullptr; // Akan diisi oleh xhook

// Fungsi pengganti untuk dlopen
void* my_dlopen_replacement(const char* filename, int flags) {
    ALOGI("XHOOKED_DLOPEN: Mencoba memuat filename='%s', flags=%d", filename, flags);

    // Panggil fungsi asli (jika perlu, tapi xhook menangani pemanggilan asli secara internal
    // saat Anda tidak secara eksplisit memanggil original_dlopen yang Anda simpan)
    // Untuk logging saja, kita biarkan xhook memanggil yang asli setelah ini.
    // Jika Anda ingin memodifikasi atau mendapatkan hasil sebelum kembali, Anda perlu
    // mendapatkan pointer ke fungsi asli dari xhook atau mekanisme lain.
    // Namun, untuk xhook, cara paling umum adalah membiarkannya memanggil yang asli
    // dan kita hanya log di sini. Jika Anda perlu hasil, Anda harus menyimpannya
    // dari xhook_call_orig.

    // Untuk mendapatkan hasil dari fungsi asli menggunakan xhook, biasanya Anda tidak
    // mendefinisikan ulang `original_dlopen` seperti ini. xhook akan memanggil
    // fungsi asli setelah fungsi pengganti Anda selesai jika Anda tidak mengintervensi.
    // Jika Anda *perlu* memanggil fungsi asli secara eksplisit dari dalam hook:
    // void* result = xhook_call_orig(my_dlopen_replacement, filename, flags);
    // ALOGI("XHOOKED_DLOPEN: Panggilan asli dlopen mengembalikan %p untuk filename='%s'", result, filename);
    // return result;
    // Untuk logging sederhana, kita tidak perlu memanggil xhook_call_orig secara manual di sini.

    // Karena kita tidak memanggil xhook_call_orig secara eksplisit, kita tidak akan
    // mendapatkan nilai kembalian di sini. xhook akan memanggil fungsi asli
    // setelah fungsi pengganti ini selesai.
    // Jika Anda ingin melihat nilai kembalian, Anda perlu meng-hook fungsi
    // yang *menggunakan* hasil dari dlopen, atau menggunakan teknik yang lebih canggih
    // dengan xhook untuk menangkap nilai kembalian.

    // Untuk tujuan logging pemanggilan, ini sudah cukup.
    // Jika Anda ingin MENGUBAH filename:
    // const char* new_filename = filename;
    // if (strcmp(filename, "path/ke/fpsensor.so") == 0) {
    //     new_filename = "path/ke/goodix.so";
    //     ALOGI("XHOOKED_DLOPEN: Mengganti filename dari '%s' ke '%s'", filename, new_filename);
    // }
    // return xhook_call_orig(my_dlopen_replacement, new_filename, flags); // Panggil asli dengan argumen baru

    return xhook_call_orig(my_dlopen_replacement, filename, flags); // Panggil fungsi asli dengan argumen asli
}

// --- Definisi Fungsi Asli dan Pengganti untuk android_dlopen_ext ---
typedef void* (*t_android_dlopen_ext)(const char* filename, int flags, const void* extinfo /*android_dlextinfo*/);
// original_android_dlopen_ext tidak perlu didefinisikan jika kita menggunakan xhook_call_orig

// Fungsi pengganti untuk android_dlopen_ext
void* my_android_dlopen_ext_replacement(const char* filename, int flags, const void* extinfo) {
    ALOGI("XHOOKED_ADLOPEN: Mencoba memuat filename='%s', flags=%d, extinfo=%p", filename, flags, extinfo);

    // Panggil fungsi asli dengan argumen asli
    return xhook_call_orig(my_android_dlopen_ext_replacement, filename, flags, extinfo);
}


static void do_hooking_with_xhook() {
    ALOGI("Memulai proses hooking dengan xhook untuk %s", TARGET_PROCESS_NAME);

    // Hook dlopen
    // Argumen ketiga adalah pointer ke fungsi pengganti kita.
    // Argumen keempat (opsional) bisa menjadi pointer untuk menyimpan fungsi asli jika diperlukan.
    // Untuk xhook, jika argumen keempat NULL, xhook akan menangani pemanggilan fungsi asli.
    if (xhook_register(".*\\libdl.so$", "dlopen", (void*)my_dlopen_replacement, nullptr) != 0 &&
        xhook_register(".*\\linker$", "dlopen", (void*)my_dlopen_replacement, nullptr) != 0 && // Linker juga bisa menyediakan dlopen
        xhook_register(".*\\libc.so$", "dlopen", (void*)my_dlopen_replacement, nullptr) != 0) { // Kadang di libc juga
        ALOGE("Gagal mendaftarkan hook untuk dlopen");
    } else {
        ALOGI("Hook untuk dlopen berhasil didaftarkan.");
    }

    // Hook android_dlopen_ext
    // Fungsi ini biasanya ada di libdl.so atau linker.
    if (xhook_register(".*\\libdl.so$", "android_dlopen_ext", (void*)my_android_dlopen_ext_replacement, nullptr) != 0 &&
        xhook_register(".*\\linker$", "android_dlopen_ext", (void*)my_android_dlopen_ext_replacement, nullptr) != 0 ) {
        ALOGE("Gagal mendaftarkan hook untuk android_dlopen_ext");
    } else {
        ALOGI("Hook untuk android_dlopen_ext berhasil didaftarkan.");
    }

    // Setelah semua hook didaftarkan, refresh cache hook
    // Argumen 0 berarti hook untuk semua proses (dalam konteks Zygisk, ini akan berlaku untuk proses target saat di-fork)
    // Argumen 1 berarti hook hanya untuk proses saat ini.
    // Karena kita berada di postAppSpecialize, proses target sudah menjadi proses saat ini.
    if (xhook_refresh(1) == 0) {
        ALOGI("xhook_refresh berhasil diterapkan.");
    } else {
        ALOGE("xhook_refresh gagal.");
    }

    // (Opsional) Aktifkan mode debug xhook jika perlu
    // xhook_enable_debug(1);
    // xhook_enable_sigsegv_protection(0); // Mungkin perlu dinonaktifkan jika ada masalah dengan SEGV handler xhook

    ALOGI("Proses hooking dengan xhook selesai.");
}


class MyXHookLoggerModule : public zygisk::ModuleBase {
public:
    void onLoad(zygisk::Api *api, JNIEnv *env) override {
        this->api = api;
        this->env = env;
        ALOGI("MyXHookLoggerModule onLoad: Modul Zygisk dimuat.");
    }

    void preAppSpecialize(zygisk::AppSpecializeArgs *args) override {
        // Dapatkan nama proses
        const char *process_name_chars = env->GetStringUTFChars(args->nice_name, nullptr);
        if (process_name_chars) {
            std::string process_name(process_name_chars);
            env->ReleaseStringUTFChars(args->nice_name, process_name_chars);

            // Periksa apakah ini proses target kita
            if (process_name == TARGET_PROCESS_NAME) {
                ALOGI("preAppSpecialize: Proses target '%s' ditemukan untuk xhook logging.", TARGET_PROCESS_NAME);
                is_target_process_for_xhook = true;
            }
        }
    }

    void postAppSpecialize(const zygisk::AppSpecializeArgs *args) override {
        if (is_target_process_for_xhook) {
            ALOGI("postAppSpecialize: Dalam proses target '%s'. Melakukan hook dengan xhook.", TARGET_PROCESS_NAME);
            
            // Menjalankan hooking di thread baru adalah praktik yang baik untuk menghindari ANR
            // jika proses hooking memakan waktu atau ada masalah startup.
            std::thread hook_thread(do_hooking_with_xhook);
            hook_thread.detach(); // Biarkan thread berjalan secara independen

            is_target_process_for_xhook = false; // Reset flag
        }
    }

private:
    zygisk::Api *api = nullptr;
    JNIEnv *env = nullptr;
    bool is_target_process_for_xhook = false;
};

// Daftarkan modul Zygisk Anda
REGISTER_ZYGISK_MODULE(MyXHookLoggerModule)
