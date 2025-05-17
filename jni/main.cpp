#include <cstring>
#include <unistd.h>
#include <cstdlib>
#include <android/log.h>
#include <xhook.h> // Anda sudah menggunakan xhook
#include <fcntl.h>
#include <sys/stat.h>
#include <stdio.h>
#include "zygisk.hpp" // Asumsi ini adalah header Zygisk dari template Anda

#define LOG_TAG "FingerprintHALExperiment" // Ganti LOG_TAG
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

// ----- HAPUS BAGIAN SnapdragonSpoof -----
// static const char *target_packages[] = { ... };
// static const size_t target_packages_count = ...;
// static const char *spoofed_props[][2] = { ... };
// static const size_t spoofed_props_count = ...;
// -----------------------------------------

// Nama proses target untuk hook open (ini perlu disesuaikan/diverifikasi)
// Biner service HAL utama Anda adalah target yang paling mungkin.
// Jika tidak tahu pasti, Anda bisa meng-hook di system_server dan melihat apakah [GF_HAL] berjalan di sana,
// atau mencoba menebak nama proses daemon HAL.
// Contoh: "/vendor/bin/hw/android.hardware.biometrics.fingerprint@2.1-service"
// atau "system_server" jika pemeriksaan device node terjadi di sana.
// Untuk eksperimen awal, mungkin lebih aman menargetkan proses HAL spesifik jika diketahui.
// Jika tidak, menargetkan semua proses dengan xhook (pattern ".*") akan terlalu luas dan berisiko.
// Kita akan mencoba menargetkan library libc.so secara umum untuk fungsi open,
// dan memfilter berdasarkan nama proses di dalam fungsi hook.
static const char *TARGET_FP_SERVICE_PROCESS_NAME = "/vendor/bin/hw/android.hardware.biometrics.fingerprint@2.1-service";
// Alternatif jika GF_HAL adalah bagian dari proses lain:
// static const char *TARGET_FP_SERVICE_PROCESS_NAME_ALT = "nama_proses_gf_hal_jika_berbeda";


// Original function pointers
static int (*orig_open)(const char* pathname, int flags, ...) = nullptr;
// Mungkin juga perlu open64 jika sistem menggunakan itu untuk path /dev
static int (*orig_open64)(const char* pathname, int flags, ...) = nullptr;
// Mungkin juga access atau stat, tapi kita mulai dengan open.
// static int (*orig_access)(const char *pathname, int mode) = nullptr;


static bool hook_applied_fp_experiment = false;
static char current_process_name_fp_exp[256] = {0};

// Utility untuk mendapatkan nama proses (sudah ada di template Anda, bisa dipakai ulang)
static const char* get_current_process_name_fp() {
    if (current_process_name_fp_exp[0] != '\0') {
        return current_process_name_fp_exp;
    }
    FILE* cmdline = fopen("/proc/self/cmdline", "r");
    if (cmdline) {
        fgets(current_process_name_fp_exp, sizeof(current_process_name_fp_exp), cmdline);
        fclose(cmdline);
        // Hapus newline jika ada
        char* newline = strchr(current_process_name_fp_exp, '\n');
        if (newline) *newline = '\0';
        
        // cmdline bisa berisi argumen lain setelah null terminator pertama,
        // jadi pastikan kita hanya mengambil bagian pertama.
        // Atau bisa juga seperti ini untuk kasus path biner absolut:
        if (strlen(current_process_name_fp_exp) == 0) { // Jika cmdline kosong, coba readlink /proc/self/exe
             ssize_t len = readlink("/proc/self/exe", current_process_name_fp_exp, sizeof(current_process_name_fp_exp) - 1);
             if (len > 0) {
                 current_process_name_fp_exp[len] = '\0';
             }
        }

        LOGI("Current process name (fp_exp): %s", current_process_name_fp_exp);
        return current_process_name_fp_exp;
    }
    LOGE("Failed to get process name (fp_exp)");
    return "unknown_process";
}


// Hook for open
extern "C" int hooked_open_fp_experiment(const char* pathname, int flags, ...) {
    mode_t mode = 0;
    // O_CREAT adalah salah satu flag yang membutuhkan argumen mode ketiga
    if ((flags & O_CREAT) == O_CREAT) {
        va_list args;
        va_start(args, flags);
        mode = (mode_t)va_arg(args, int); // mode_t sering di-pass sebagai int
        va_end(args);
    }

    const char* current_proc = get_current_process_name_fp();
    bool is_target_process = (strcmp(current_proc, TARGET_FP_SERVICE_PROCESS_NAME) == 0);
                               // Tambahkan || strcmp(current_proc, TARGET_FP_SERVICE_PROCESS_NAME_ALT) == 0 jika ada alternatif

    if (is_target_process && pathname && strcmp(pathname, "/dev/goodix_fp") == 0) {
        LOGI("hooked_open_fp_experiment: Intercepted open for /dev/goodix_fp in target process %s. Flags: %d", current_proc, flags);
        
        // Strategi: Kembalikan FD dari /dev/null agar pemeriksaan "keberadaan" berhasil,
        // tetapi operasi selanjutnya pada FD ini kemungkinan akan gagal atau tidak berarti.
        // Ini akan menguji apakah [GF_HAL] melanjutkan jika ia mengira device node ada.
        int fd_dev_null = -1;
        if (orig_open) { // Panggil open asli untuk /dev/null
             fd_dev_null = orig_open("/dev/null", O_RDWR); 
        }
        LOGI("hooked_open_fp_experiment: For /dev/goodix_fp, returning FD of /dev/null: %d", fd_dev_null);
        return fd_dev_null;
    }

    // Panggil fungsi open asli untuk path lain atau proses lain
    if (orig_open) {
        if ((flags & O_CREAT) == O_CREAT) {
            return orig_open(pathname, flags, mode);
        } else {
            return orig_open(pathname, flags);
        }
    }
    // Fallback jika orig_open tidak ter-resolve (seharusnya tidak terjadi jika xhook berhasil)
    LOGE("hooked_open_fp_experiment: orig_open is null!");
    errno = EACCES; // Kembalikan error yang masuk akal
    return -1;
}

// Hook untuk open64 (sering digunakan untuk file besar atau device node)
extern "C" int hooked_open64_fp_experiment(const char* pathname, int flags, ...) {
    mode_t mode = 0;
    if ((flags & O_CREAT) == O_CREAT) {
        va_list args;
        va_start(args, flags);
        mode = (mode_t)va_arg(args, int);
        va_end(args);
    }

    const char* current_proc = get_current_process_name_fp();
    bool is_target_process = (strcmp(current_proc, TARGET_FP_SERVICE_PROCESS_NAME) == 0);

    if (is_target_process && pathname && strcmp(pathname, "/dev/goodix_fp") == 0) {
        LOGI("hooked_open64_fp_experiment: Intercepted open64 for /dev/goodix_fp in target process %s. Flags: %d", current_proc, flags);
        int fd_dev_null = -1;
        if (orig_open64) {
             fd_dev_null = orig_open64("/dev/null", O_RDWR);
        } else if (orig_open) { // Fallback ke orig_open jika orig_open64 tidak dihook/ditemukan
             fd_dev_null = orig_open("/dev/null", O_RDWR);
        }
        LOGI("hooked_open64_fp_experiment: For /dev/goodix_fp, returning FD of /dev/null: %d", fd_dev_null);
        return fd_dev_null;
    }

    if (orig_open64) {
        if ((flags & O_CREAT) == O_CREAT) {
            return orig_open64(pathname, flags, mode);
        } else {
            return orig_open64(pathname, flags);
        }
    } else if (orig_open) { // Fallback jika orig_open64 tidak dihook/ditemukan
         if ((flags & O_CREAT) == O_CREAT) {
            return orig_open(pathname, flags, mode);
        } else {
            return orig_open(pathname, flags);
        }
    }
    LOGE("hooked_open64_fp_experiment: orig_open64 (and orig_open) is null!");
    errno = EACCES;
    return -1;
}


static void apply_fp_experiment_hooks(const char* process_name) {
    if (hook_applied_fp_experiment) {
        // LOGI("FP Experiment hooks already applied for %s, skipping", process_name);
        return;
    }

    // Hanya pasang hook jika ini adalah proses target kita
    if (strcmp(process_name, TARGET_FP_SERVICE_PROCESS_NAME) != 0) {
        // LOGI("Not the target FP service process (%s), skipping hooks.", process_name);
        return;
    }
    
    LOGI("Installing FP Experiment hooks for process: %s", process_name);
    // xhook_clear(); // Hati-hati jika ada hook lain yang ingin dipertahankan dari template asli.
                   // Jika ini satu-satunya set hook, maka clear OK. Jika tidak, jangan clear.
                   // Untuk sekarang, kita asumsikan kita ingin mengganti semua logika hook.
    
    // Kita akan hook libc.so karena 'open' adalah fungsi libc standar
    const char* pattern_libc = "libc\\.so$"; 
    // Atau bisa juga ".*" untuk semua library, tapi lebih baik spesifik jika memungkinkan.
    // Jika service HAL di-link secara statis dengan libc versi lain, pattern perlu disesuaikan.

    int ret_open = xhook_register(pattern_libc, "open",
        (void*)hooked_open_fp_experiment, (void**)&orig_open);
    int ret_open64 = xhook_register(pattern_libc, "open64",
        (void*)hooked_open64_fp_experiment, (void**)&orig_open64);

    // Anda juga bisa menambahkan hook untuk "access" atau "stat" jika 'open' tidak cukup
    // int ret_access = xhook_register(pattern_libc, "access", ...);

    int ret_refresh = xhook_refresh(0); // Terapkan semua hook yang terdaftar

    bool success = (ret_open == 0) && (ret_open64 == 0) && (ret_refresh == 0);

    if (success) {
        LOGI("FP Experiment hook injection completed successfully for %s!", process_name);
        hook_applied_fp_experiment = true;
    } else {
        LOGE("Failed to apply one or more FP Experiment hooks for %s!", process_name);
        if (ret_open != 0) LOGE("open hook failed: %d", ret_open);
        if (ret_open64 != 0) LOGE("open64 hook failed: %d", ret_open64);
        if (ret_refresh != 0) LOGE("xhook_refresh failed: %d", ret_refresh);
    }
}

// Anda perlu cara untuk memanggil apply_fp_experiment_hooks
// dari dalam fungsi yang disediakan Zygisk (misalnya preAppSpecialize atau preServerSpecialize)
// dan hanya untuk proses target.

class MyModule : public zygisk::ModuleBase {
public:
    void onLoad(zygisk::Api* api, JNIEnv* env) override {
        this->api = api;
        this->env = env;
        LOGI("FingerprintHALExperiment Zygisk module loaded");
    }

    // Hook untuk proses aplikasi (termasuk beberapa proses sistem yang di-fork dari Zygote seperti aplikasi)
    void preAppSpecialize(zygisk::AppSpecializeArgs* args) override {
        const char* process_name = env->GetStringUTFChars(args->nice_name, nullptr);
        if (process_name) {
            // Simpan nama proses untuk digunakan nanti jika perlu
            strncpy(current_process_name_fp_exp, process_name, sizeof(current_process_name_fp_exp) -1);
            current_process_name_fp_exp[sizeof(current_process_name_fp_exp)-1] = '\0';

            // Kita lebih tertarik pada proses HAL native atau system_server
            // jadi mungkin tidak melakukan hook di sini, kecuali jika proses HAL di-spawn sebagai app.
            // Untuk sekarang, kita coba hook di preServerSpecialize juga.
            // LOGI("preAppSpecialize: process_name=%s, uid=%d", process_name, args->uid);
            
            // Jika service HAL berjalan sebagai proses aplikasi biasa (jarang untuk HAL sistem)
            // if (strcmp(process_name, TARGET_FP_SERVICE_PROCESS_NAME) == 0) {
            //     apply_fp_experiment_hooks(process_name);
            // }
            env->ReleaseStringUTFChars(args->nice_name, process_name);
        }
    }
    
    // Hook untuk system_server
    void preServerSpecialize(zygisk::ServerSpecializeArgs* args) override {
        // system_server adalah kandidat kuat jika pengecekan device node terjadi di framework Java
        // atau jika service HAL di-load dari dalam system_server.
        // Namun, service HAL fingerprint biasanya berjalan sebagai prosesnya sendiri.
        // Kita akan tetap mencoba mendapatkan nama proses aktual di mana hook open akan berjalan.
        // Untuk Zygisk, lebih baik hook dipasang saat proses target itu sendiri sedang dibuat,
        // yang mungkin lebih sulit ditangkap di sini jika proses HAL bukan Zygote-forked app atau system_server.

        // Untuk contoh ini, kita akan berasumsi hook open akan berjalan di proses yang relevan
        // dan kita akan memfilter berdasarkan nama proses di dalam fungsi hook itu sendiri.
        // Pendekatan yang lebih baik adalah menggunakan Zygisk API untuk hook pada saat proses target di-fork.
        // Namun, xhook bekerja dengan me-resolve simbol saat runtime, jadi kita bisa menginisialisasinya
        // dan hook akan aktif ketika library target (libc.so) dimuat oleh proses target.
        
        // Kita akan panggil apply_fp_experiment_hooks dengan nama proses yang kita ketahui adalah TARGET.
        // Ini berarti kita MENGASUMSIKAN bahwa ketika TARGET_FP_SERVICE_PROCESS_NAME
        // dimulai, libc.so akan dimuat dan xhook akan bisa bekerja.
        // Cara yang lebih Zygisk-native adalah menggunakan api->hookJniNativeMethods atau api->pltHookRegister
        // jika Anda tahu simbol spesifik di library target, atau men-patch ELF.
        // Karena xhook sudah ada, kita coba manfaatkan.

        LOGI("preServerSpecialize called. Applying hooks for potential HAL process.");
        // Karena xhook me-resolve simbol saat runtime, kita daftarkan saja.
        // Pemfilteran nama proses akan dilakukan di dalam fungsi hook `open`.
        // Ini akan meng-hook `open` di semua proses yang di-fork dari Zygote yang memuat libc.so,
        // jadi pemfilteran di dalam `hooked_open_fp_experiment` sangat penting.
        // Atau, kita bisa pasang hook di sini dan berharap proses HAL akan kena.
        
        // Untuk kesederhanaan, kita pasang hook secara global dan filter di dalam fungsi hook
        // Ini kurang ideal untuk Zygisk, tapi memanfaatkan xhook yang ada.
        apply_global_fp_hooks();
    }

private:
    zygisk::Api* api;
    JNIEnv* env;

    void apply_global_fp_hooks() {
        if (hook_applied_fp_experiment) {
            LOGI("Global FP Experiment hooks already applied, skipping");
            return;
        }
        LOGI("Installing Global FP Experiment hooks (will filter by process name inside hook)");
        
        const char* pattern_libc = "libc\\.so$"; 

        int ret_open = xhook_register(pattern_libc, "open",
            (void*)hooked_open_fp_experiment, (void**)&orig_open);
        int ret_open64 = xhook_register(pattern_libc, "open64",
            (void*)hooked_open64_fp_experiment, (void**)&orig_open64);

        int ret_refresh = xhook_refresh(0);

        bool success = (ret_open == 0) && (ret_open64 == 0) && (ret_refresh == 0);

        if (success) {
            LOGI("Global FP Experiment hook registration completed successfully!");
            hook_applied_fp_experiment = true;
        } else {
            LOGE("Failed to apply one or more Global FP Experiment hooks!");
            if (ret_open != 0) LOGE("Global open hook failed: %d", ret_open);
            if (ret_open64 != 0) LOGE("Global open64 hook failed: %d", ret_open64);
            if (ret_refresh != 0) LOGE("Global xhook_refresh failed: %d", ret_refresh);
        }
    }
};

// Daftarkan modul Zygisk Anda
REGISTER_ZYGISK_MODULE(MyModule)

// Jika Anda ingin mengaktifkan hook saat library dimuat (misalnya, jika di-inject ke proses tertentu nanti)
// Anda bisa menggunakan __attribute__((constructor))
// __attribute__((constructor)) static void onLibraryLoad() {
//    const char* proc_name = get_current_process_name_fp();
//    if (strcmp(proc_name, TARGET_FP_SERVICE_PROCESS_NAME) == 0) {
//       LOGI("FP Experiment Library loaded into target process: %s", proc_name);
//       apply_fp_experiment_hooks(proc_name);
//    } else {
//       LOGI("FP Experiment Library loaded into non-target process: %s", proc_name);
//    }
// }