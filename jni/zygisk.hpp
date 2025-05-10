#pragma once

#include <jni.h>

namespace zygisk {

enum class Status {
    DISABLED,
    UNSUPPORTED,
    ACTIVE,
};

enum : int {
    PROCESS_DAEMON,
    PROCESS_MAIN,
    PROCESS_COMPANION,
    PROCESS_APP_ZYGOTE,
    PROCESS_SYSTEM_SERVER,
};

struct AppSpecializeArgs {
    jint &uid;
    jint &gid;
    jintArray &gids;
    jint &runtime_flags;
    jobjectArray &mount_external;
    jstring &se_info;
    jstring &nice_name;
    jstring &instruction_set;
    jstring &app_data_dir;

    jboolean *const is_child_zygote;
    jboolean *const is_top_app;
    jobjectArray *const pkg_data_info_list;
    jobjectArray *const whitelisted_data_info_list;
    jboolean *const mount_data_dirs;
    jboolean *const mount_storage_dirs;
};

struct ServerSpecializeArgs {
    jint &uid;
    jint &gid;
    jintArray &gids;
    jint &runtime_flags;
    jlong &permitted_capabilities;
    jlong &effective_capabilities;
};

class Api {
public:
    virtual bool connectCompanion() = 0;
    virtual int getCompanionFd() = 0;
    virtual void setOption(const int option) = 0;
    virtual void setOption(const int option, const bool value) = 0;
    virtual int getApiVersion() = 0;

protected:
    ~Api() = default;
};

class ModuleBase {
public:
    ModuleBase() = default;
    virtual ~ModuleBase() = default;

    virtual void onLoad(Api *api, JNIEnv *env) {}
    virtual void preAppSpecialize(AppSpecializeArgs *args) {}
    virtual void postAppSpecialize(const AppSpecializeArgs *args) {}
    virtual void preServerSpecialize(ServerSpecializeArgs *args) {}
    virtual void postServerSpecialize(const ServerSpecializeArgs *args) {}
};

} // <--- TUTUP namespace zygisk HARUS DISINI

// ---- ENTRY POINT ZYGISK WAJIB: POINTER TO POINTER DAN LINKAGE C ----
#ifdef __cplusplus
extern "C" {
#endif
void registerModule(zygisk::ModuleBase **module);
#ifdef __cplusplus
}
#endif