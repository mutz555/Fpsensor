LOCAL_PATH := $(call my-dir)

# Define Dobby library path
DOBBY_DIR := $(LOCAL_PATH)/dobby

# First build the Dobby library if it doesn't exist
ifneq ($(wildcard $(LOCAL_PATH)/libdobby.so),)
    # Dobby library already exists, do nothing
else
    $(info Building Dobby library...)
    $(shell cd $(DOBBY_DIR) && mkdir -p build && cd build && cmake .. -DCMAKE_BUILD_TYPE=Release -DDOBBY_BUILD_SHARED_LIBRARY=ON && make)
    $(shell cp $(DOBBY_DIR)/build/libdobby.so $(LOCAL_PATH)/)
 endif

# Build our module
include $(CLEAR_VARS)
LOCAL_MODULE := fingerprint_bypasser
LOCAL_SRC_FILES := main.cpp
LOCAL_STATIC_LIBRARIES := libcxx
LOCAL_LDLIBS := -llog -ldl
LOCAL_CFLAGS += -std=c++17 -fno-rtti -fno-exceptions -DDOBBY_ANDROID

# Include Dobby headers
LOCAL_C_INCLUDES += $(LOCAL_PATH)/dobby/include

# Link against Dobby library
LOCAL_LDFLAGS += -L$(LOCAL_PATH) -ldobby

include $(BUILD_SHARED_LIBRARY)

$(call import-module,libcxx)
