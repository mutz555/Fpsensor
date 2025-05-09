LOCAL_PATH := $(call my-dir)

# Modul static library untuk xhook, masukkan SEMUA file .c yang terkait
include $(CLEAR_VARS)
LOCAL_MODULE := xhook
LOCAL_SRC_FILES := \
    xhook.c \
    xh_core.c \
    xh_util.c \
    xh_log.c \
    xh_elf.c \
    xh_jni.c \
    xh_version.c
include $(BUILD_STATIC_LIBRARY)

# Modul utama fingerprint_bypasser
include $(CLEAR_VARS)
LOCAL_MODULE := fingerprint_bypasser
LOCAL_SRC_FILES := main.cpp / zygisk.cpp / module.cpp
LOCAL_STATIC_LIBRARIES := xhook
LOCAL_LDLIBS := -llog -ldl
LOCAL_CFLAGS += -fno-rtti -fno-exceptions -DDISABLE_DOBBY_HOOK
LOCAL_CPPFLAGS += -std=c++17 -DNO_DOBBY_LIBRARY
LOCAL_CFLAGS += -O0 -g
LOCAL_CPPFLAGS += -O0 -g
include $(BUILD_SHARED_LIBRARY)