LOCAL_PATH := $(call my-dir)

# Build our module without external dependencies
include $(CLEAR_VARS)
LOCAL_MODULE := fingerprint_bypasser
# Make sure we only use main.cpp and no other file
LOCAL_SRC_FILES := main.cpp
LOCAL_STATIC_LIBRARIES := libcxx
LOCAL_LDLIBS := -llog -ldl
LOCAL_CFLAGS += -std=c++17 -fno-rtti -fno-exceptions -DDISABLE_DOBBY_HOOK

# Define that we're not using Dobby
LOCAL_CPPFLAGS += -DNO_DOBBY_LIBRARY

# Explicitly disable all external libraries (including Dobby)
LOCAL_SHARED_LIBRARIES :=

include $(BUILD_SHARED_LIBRARY)

# Only import libcxx, no other external dependencies
$(call import-module,libcxx)
