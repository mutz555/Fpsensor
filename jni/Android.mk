LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
LOCAL_MODULE := fingerprint_bypasser
LOCAL_SRC_FILES := main.cpp xhook.c

# C flags khusus untuk file .c (xhook.c)
LOCAL_CFLAGS := -fno-rtti -fno-exceptions -DDISABLE_DOBBY_HOOK

# C++ flags khusus untuk file .cpp (main.cpp)
LOCAL_CPPFLAGS := -std=c++17 -DNO_DOBBY_LIBRARY

LOCAL_LDLIBS := -llog -ldl
LOCAL_SHARED_LIBRARIES :=

include $(BUILD_SHARED_LIBRARY)