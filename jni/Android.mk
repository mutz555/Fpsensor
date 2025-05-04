LOCAL_PATH := $(call my-dir)

# ===== Modul Static Library untuk xhook (SEMUA file C-nya disebutkan) =====
include $(CLEAR_VARS)
LOCAL_MODULE := xhook
LOCAL_SRC_FILES := xhook.c xh_core.c xh_util.c
include $(BUILD_STATIC_LIBRARY)

# ===== Modul Shared Library utama (file C++ saja) =====
include $(CLEAR_VARS)
LOCAL_MODULE := fingerprint_bypasser
LOCAL_SRC_FILES := main.cpp
LOCAL_STATIC_LIBRARIES := xhook
LOCAL_LDLIBS := -llog -ldl
LOCAL_CFLAGS += -fno-rtti -fno-exceptions -DDISABLE_DOBBY_HOOK
LOCAL_CPPFLAGS += -std=c++17 -DNO_DOBBY_LIBRARY
include $(BUILD_SHARED_LIBRARY)