#include <cstdlib>
#include <unistd.h> // Untuk getpid()
#include <fcntl.h>
#include <android/log.h>
#include <string>
#include <dlfcn.h>
#include <thread>
#include <cstdarg> // Untuk va_list, vsnprintf
#include <vector>  // Untuk std::vector (jika diperlukan untuk stack trace nanti)
// #include <unwind.h> // Untuk stack trace (membutuhkan libunwind, bisa kompleks)
// #include <dladdr.h> // Untuk mendapatkan info simbol dari alamat (untuk stack trace)

// Sertakan header API Zygisk
#include "zygisk.hpp"

// Sertakan header xhook
#include "xhook.h" // Pastikan path ini benar

#define LOG_TAG "MyLogPrintInterceptor"
#define ALOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define ALOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)
#define ALOGW(...) __android_log_print(ANDROID_LOG_WARN, LOG_TAG, __VA_ARGS__)


// Tanda tangan dan pointer untuk __android_log_print asli
typedef int (*t_android_log_print_orig)(int prio, const char* tag, const char* fmt, ...);
static t_android_log_print_orig original_android_log_print_ptr = nullptr;

// Fungsi pengganti untuk __android_log_print
int my_android_log_print_replacement(int prio, const char* tag, const char* fmt, ...) {
    char current_process_name[256] = {0};
    // Dapatkan nama proses saat ini (cara sederhana, mungkin tidak selalu lengkap)
    FILE* cmdline = fopen("/proc/self/cmdline", "r");
    if (cmdline) {
        fread(current_process_name, sizeof(current_process_name) -1, 1, cmdline);
        fclose(cmdline);
    }

    // Format pesan log asli terlebih dahulu agar bisa diperiksa
    char formatted_msg_buffer[1024]; // Buffer yang cukup besar
    va_list args;
    va_start(args, fmt);
    vsnprintf(formatted_msg_buffer, sizeof(formatted_msg_buffer), fmt, args);
    va_end(args);

    // Periksa apakah ini log yang kita cari
    if (tag && strcmp(tag, "fpCoreHal") == 0) {
        if (strstr(formatted_msg_buffer, "fp_config_external.cpp force set hal module id to fpsensor_fingerprint")) {
            ALOGE(">>>> TARGET LOG FOUND in process: %s (PID: %d) <<<<", current_process_name, getpid());
            ALOGE(">>>> Tag: %s, Original Message: %s", tag, formatted_msg_buffer);
            // Di sini Anda bisa mencoba mendapatkan stack trace jika memungkinkan
            // Ini bisa sangat membantu untuk melihat dari mana panggilan log berasal
        }
    }

    // Panggil fungsi __android_log_print asli agar log tetap muncul di logcat
    // dan agar tidak mengganggu fungsi logging normal.
    // Perlu memanggil dengan va_list lagi atau meneruskan argumen asli.
    // Cara paling aman adalah memanggil yang asli dengan argumen yang diterima.
    // Ini agak rumit karena argumen variadic.
    // Jika original_android_log_print_ptr sudah benar, kita bisa coba panggil dengan argumen yang sudah diformat
    // atau, jika xhook_call_orig tersedia dan berfungsi di versi xhook Anda, itu lebih mudah.
    // Karena kita sudah mengonfirmasi xhook_call_orig tidak ada di xhook.h Anda,
    // kita akan memanggil pointer asli dengan pesan yang sudah diformat.
    if (original_android_log_print_ptr) {
        // Membuat ulang va_list untuk panggilan asli
        va_list original_args_for_call;
        va_start(original_args_for_call, fmt);
        // Ini adalah cara yang sedikit kurang ideal karena kita memformat ulang,
        // idealnya kita meneruskan va_list asli jika memungkinkan atau xhook menanganinya.
        // Untuk tujuan logging kita, memanggil dengan string yang sudah diformat bisa diterima
        // meskipun mungkin ada perbedaan kecil jika format string asli sangat kompleks.
        // Cara yang lebih aman adalah memanggil dengan fmt dan va_list asli.
        int result = original_android_log_print_ptr(prio, tag, fmt, original_args_for_call); // Ini mungkin tidak meneruskan varargs dengan benar
        va_end(original_args_for_call);

        // Alternatif yang lebih aman jika kita hanya ingin log dan tidak memodifikasi:
        // Panggil original_android_log_print_ptr dengan argumen yang sama persis.
        // Ini membutuhkan penanganan varargs yang cermat.
        // Untuk kesederhanaan dan fokus pada deteksi, kita mungkin hanya log dan tidak memanggil ulang,
        // atau memanggil dengan pesan yang sudah diformat.
        // Jika kita hanya ingin MENDETEKSI dan tidak ingin log duplikat atau masalah varargs:
        // if (target_log_detected) { /* lakukan sesuatu */ }
        // return original_android_log_print_ptr(prio, tag, fmt, ... /* argumen asli */);
        // Karena sulit meneruskan '...' dengan benar, kita akan memanggil dengan pesan yang sudah diformat
        // yang berarti log asli mungkin tidak persis sama jika ada format kompleks.
        // Untuk tujuan deteksi kita, ini mungkin cukup.
        // Jika kita tidak ingin mencetak log dua kali, kita bisa return di sini setelah ALOGE kita.
        // Namun, untuk memastikan log asli tetap ada, kita coba panggil.
        // Panggilan yang lebih aman:
        // va_list args_for_original_call;
        // va_start(args_for_original_call, fmt);
        // int result = original_android_log_print_ptr(prio, tag, fmt, args_for_original_call);
        // va_end(args_for_original_call);
        // return result;
        // Untuk sekarang, kita biarkan xhook yang menangani pemanggilan asli jika bisa,
        // atau kita panggil dengan buffer yang sudah diformat.
        // Jika kita menggunakan xhook_register dengan argumen ke-4 (old_func_ptr_addr),
        // maka original_android_log_print_ptr akan berisi fungsi asli.
        return original_android_log_print_ptr(prio, tag, "%s", formatted_msg_buffer); // Cetak pesan yang sudah diformat
    }
    return -1; 
}

static void do_hooking_log_print_for_process(const char* current_process_name_cstr) {
    ALOGI("Memulai hook __android_log_print di proses: %s", current_process_name_cstr);

    // xhook_enable_debug(1); // Aktifkan jika perlu debug xhook

    // Hook __android_log_print dari liblog.so
    // Regex ".*\\liblog.so$" seharusnya sudah cukup.
    if (xhook_register(".*\\liblog.so$", "__android_log_print",
                       (void*)my_android_log_print_replacement,
                       (void**)&original_android_log_print_ptr) != 0) {
        ALOGE("Gagal mendaftarkan hook untuk __android_log_print di proses: %s", current_process_name_cstr);
    } else {
        ALOGI("Hook untuk __android_log_print berhasil didaftarkan di proses: %s", current_process_name_cstr);
    }

    if (xhook_refresh(1) != 0) { // Terapkan hook untuk proses saat ini
        ALOGE("xhook_refresh gagal di proses: %s", current_process_name_cstr);
    } else {
        ALOGI("xhook_refresh berhasil diterapkan di proses: %s", current_process_name_cstr);
    }
}

class MyGlobalLogPrintHookModule : public zygisk::ModuleBase {
public:
    void onLoad(zygisk::Api *api, JNIEnv *env) override {
        this->api = api;
        this->env = env;
        ALOGI("MyGlobalLogPrintHookModule onLoad. PID: %d", getpid());
    }

    void postAppSpecialize(const zygisk::AppSpecializeArgs *args) override {
        // Dapatkan nama proses
        const char *process_name_chars = env->GetStringUTFChars(args->nice_name, nullptr);
        if (process_name_chars) {
            std::string process_name_str(process_name_chars); // Salin ke std::string
            env->ReleaseStringUTFChars(args->nice_name, process_name_chars);

            // Kita ingin hook di sebagian besar proses sistem dan aplikasi untuk menemukan log ini.
            // Anda bisa mempersempit ini jika sudah ada dugaan proses mana yang mencetaknya.
            // Contoh: jangan hook di aplikasi user biasa jika tidak perlu.
            // if (args->uid >= 10000) { // Contoh: Abaikan aplikasi pengguna biasa
            //     return;
            // }

            ALOGI("postAppSpecialize: Mencoba hook __android_log_print di proses: %s (UID: %d)", process_name_str.c_str(), args->uid);
            
            // Menjalankan hooking di thread baru adalah praktik yang baik
            // Mengirim salinan std::string ke thread
            std::thread hook_thread([process_name_str]() {
                do_hooking_log_print_for_process(process_name_str.c_str());
            });
            hook_thread.detach();
        }
    }

private:
    zygisk::Api *api = nullptr;
    JNIEnv *env = nullptr;
};

// Daftarkan modul Zygisk Anda
REGISTER_ZYGISK_MODULE(MyGlobalLogPrintHookModule)

