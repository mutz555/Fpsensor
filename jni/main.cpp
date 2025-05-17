#include <cstring>
#include <string>
#include <android/log.h>
#include "zygisk.hpp" // Header Zygisk Anda

#define LOG_TAG "FPProcessScan" // TAG baru untuk debugging ini
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN, LOG_TAG, __VA_ARGS__)

class ProcessScanModule : public zygisk::ModuleBase {
public:
    void onLoad(zygisk::Api* api, JNIEnv* env) override {
        this->api = api;
        this->env = env;
        LOGI("ProcessScanModule Zygisk module loaded (onLoad).");
    }

    void postAppSpecialize(const zygisk::AppSpecializeArgs* args) override {
        if (!args || !args->nice_name) {
            // LOGW("postAppSpecialize: args or nice_name is null."); // Bisa diaktifkan jika perlu
            return;
        }

        const char* raw_process_nice_name = env->GetStringUTFChars(args->nice_name, nullptr);
        if (!raw_process_nice_name) {
            // LOGW("postAppSpecialize: Failed to get nice_name chars."); // Bisa diaktifkan jika perlu
            return;
        }
        std::string current_process_nice_name_str = raw_process_nice_name;
        env->ReleaseStringUTFChars(args->nice_name, raw_process_nice_name);

        // Catat SEMUA proses yang melewati postAppSpecialize
        LOGI("postAppSpecialize: Scanned process nice_name: '%s', UID: %d, PID: %d",
             current_process_nice_name_str.c_str(), args->uid, getpid());
    }

    void preServerSpecialize(zygisk::ServerSpecializeArgs* args) override {
        LOGI("preServerSpecialize called. UID: %d. System server UID: %d. PID: %d", getuid(), args->uid, getpid());
        // Anda juga bisa mencatat nice_name system_server jika tersedia melalui mekanisme lain di sini jika perlu
    }

private:
    zygisk::Api* api = nullptr;
    JNIEnv* env = nullptr;
};

REGISTER_ZYGISK_MODULE(ProcessScanModule)
```

**Langkah Berikutnya dengan Kode Debug Ini:**
1.  Gunakan kode di atas untuk `main.cpp` Anda.
2.  Build, instal, dan aktifkan modul Zygisk ini.
3.  Reboot perangkat FPC Anda.
4.  Setelah boot, ambil logcat dengan `adb logcat -s FPProcessScan`.
5.  Sambil itu, dari shell ADB, jalankan `ps -A -o PID,UID,NAME,CMDLINE | grep -E "fingerprint|biometric|goodix|fpsensor"` untuk menemukan PID dan nama proses pasti dari service HAL sidik jari Anda yang sedang berjalan.
6.  Bandingkan PID/UID dari `ps` dengan yang dicatat oleh modul Zygisk Anda untuk menemukan `nice_name` yang benar.

Jika service HAL sidik jari Anda (`/vendor/bin/hw/android.hardware.biometrics.fingerprint@2.1-service`) **tidak muncul** di log `FPProcessScan` dari `postAppSpecialize` (atau `nice_name`-nya sangat berbeda dari yang Anda harapkan), maka kita perlu memikirkan cara lain untuk menargetkan proses tersebut untuk hook native, karena Zygisk `postAppSpecialize` mungkin bukan tempat yang tepat untuk mencegatn