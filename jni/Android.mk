LOCAL_PATH := $(call my-dir)

# Modul static library untuk xhook
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

# Modul utama Zygisk spoof s24
include $(CLEAR_VARS)
LOCAL_MODULE := zygisk_spoofs24
LOCAL_SRC_FILES := main.cpp
LOCAL_STATIC_LIBRARIES := xhook
LOCAL_LDLIBS := -llog -ldl
LOCAL_CFLAGS += -fno-rtti -fno-exceptions -DISABLE_DOBBY_HOOK -O0 -g
LOCAL_CPPFLAGS += -std=c++17 -DNO_DOBBY_LIBRARY -O0 -g
include $(BUILD_SHARED_LIBRARY)