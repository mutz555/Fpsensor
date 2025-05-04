LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
LOCAL_MODULE := module
LOCAL_SRC_FILES := module.cpp zygisk_main.cpp
LOCAL_STATIC_LIBRARIES := libcxx
LOCAL_LDLIBS := -llog
include $(BUILD_SHARED_LIBRARY)

include $(CLEAR_VARS)
LOCAL_MODULE := libcxx
LOCAL_SRC_FILES := 
include $(BUILD_STATIC_LIBRARY)