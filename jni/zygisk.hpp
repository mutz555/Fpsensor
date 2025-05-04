#pragma once

#include <jni.h>

namespace zygisk {

    // Manages the status of the current service daemon
    enum class Status {
        // The module is currently disabled
        DISABLED,
        // The module is running in the unsupported old app process hook mode
        // due to old Magisk version
        UNSUPPORTED,
        // The module is running properly
        ACTIVE,
    };

    // These values are used in Magisk's internal communication
    // and should not be modified
    enum : int {
        PROCESS_DAEMON,
        PROCESS_MAIN,
        PROCESS_COMPANION,
        PROCESS_APP_ZYGOTE,
        PROCESS_SYSTEM_SERVER,
    };

    // Contains information regarding the current process
    struct AppSpecializeArgs {
        // Required arguments. These arguments are guaranteed to exist on all Android versions.
        jint &uid;              /* = getuid() */
        jint &gid;              /* = getgid() */
        jintArray &gids;        /* supplementary groups */
        jint &runtime_flags;
        jobjectArray &mount_external;   /* mount points */
        jstring &se_info;
        jstring &nice_name;
        jstring &instruction_set;
        jstring &app_data_dir;   /* Android 5.0+ */

        // Optional arguments. Please check for null before using them.
        jboolean *const is_child_zygote;  /* Android 5.0+ */
        jboolean *const is_top_app;       /* Android 8.0+ */
        jobjectArray *const pkg_data_info_list; /* Android 8.0+ */
        jobjectArray *const whitelisted_data_info_list; /* Android 11.0+ */
        jboolean *const mount_data_dirs; /* Android 11.0+ */
        jboolean *const mount_storage_dirs; /* Android 11.0+ */
    };

    // Contains information regarding the current process (system_server specialized)
    struct ServerSpecializeArgs {
        jint &uid;          /* = getuid() */
        jint &gid;          /* = getgid() */
        jintArray &gids;    /* supplementary groups */
        jint &runtime_flags;
        jlong &permitted_capabilities;
        jlong &effective_capabilities;
    };

    // The api to interact with Zygisk
    class Api {
    public:
        // Connect the companion daemon component
        // Returns false if the connection attempt failed
        virtual bool connectCompanion() = 0;

        // Get the file descriptor of the companion daemon, -1 if not connected
        virtual int getCompanionFd() = 0;

        // Set the module's status to Status::DISABLED when the module is dlclose-d
        // WARNING: Should only be called when unloading the module.
        // WARNING: Should only be called on the module unloading thread.
        virtual void setOption(const int option) = 0;

        // Apply process restrictions as if the module does not exist.
        // WARNING: Should only be called on the main thread.
        // WARNING: Should only be called in preAppSpecialize or preServerSpecialize.
        virtual void setOption(const int option, const bool value) = 0;

        // Get the Zygisk API version that the current Magisk is using.
        virtual int getApiVersion() = 0;

    protected:
        ~Api() = default;
    };

    // The main API for a Zygisk module
    class ModuleBase {
    public:
        ModuleBase() = default;

        virtual ~ModuleBase() = default;

        // This method is called when the module is loaded in zygote by Magisk
        virtual void onLoad(Api *api, JNIEnv *env) {}

        // This method is called before common app processes are specialized
        // WARNING: Should only be called on the main thread.
        virtual void preAppSpecialize(AppSpecializeArgs *args) {}

        // This method is called after common app processes are specialized
        // WARNING: Should only be called on the main thread.
        virtual void postAppSpecialize(const AppSpecializeArgs *args) {}

        // This method is called before system server is specialized
        // WARNING: Should only be called on the main thread.
        virtual void preServerSpecialize(ServerSpecializeArgs *args) {}

        // This method is called after system server is specialized
        // WARNING: Should only be called on the main thread.
        virtual void postServerSpecialize(const ServerSpecializeArgs *args) {}
    };

    // Register your own module
    // After registering a module, the methods of that module will be called accordingly
    void registerModule(ModuleBase *module);
}

// Registers a module using the default constructor
// This is the recommended way to register a module
#define REGISTER_ZYGISK_MODULE(clazz) \  /* NOLINT */ \
__attribute__((constructor)) static void zygiskModuleRegister() { \
    static clazz module; \
    zygisk::registerModule(&module); \
}