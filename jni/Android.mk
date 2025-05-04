LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
LOCAL_MODULE := fingerprint_bypasser
LOCAL_SRC_FILES := main.cpp xhook.c
LOCAL_LDLIBS := -llog -ldl
LOCAL_CFLAGS += -std=c++17 -fno-rtti -fno-exceptions -DDISABLE_DOBBY_HOOK
LOCAL_CPPFLAGS += -DNO_DOBBY_LIBRARY
LOCAL_SHARED_LIBRARIES :=

include $(BUILD_SHARED_LIBRARY)