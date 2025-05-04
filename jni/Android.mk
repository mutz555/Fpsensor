LOCAL_PATH := $(call my-dir)

# Modul static library untuk xhook (file C)
include $(CLEAR_VARS)
LOCAL_MODULE := xhook
LOCAL_SRC_FILES := xhook.c
include $(BUILD_STATIC_LIBRARY)

# Modul utama fingerprint_bypasser (file C++)
include $(CLEAR_VARS)
LOCAL_MODULE := fingerprint_bypasser
LOCAL_SRC_FILES := main.cpp
LOCAL_STATIC_LIBRARIES := xhook
LOCAL_LDLIBS := -llog -ldl
LOCAL_CFLAGS += -fno-rtti -fno-exceptions -DDISABLE_DOBBY_HOOK
LOCAL_CPPFLAGS += -std=c++17 -DNO_DOBBY_LIBRARY
include $(BUILD_SHARED_LIBRARY)