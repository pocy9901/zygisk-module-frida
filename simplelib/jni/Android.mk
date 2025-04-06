LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
LOCAL_MODULE := shadowhook
LOCAL_SRC_FILES := ../shadowhook/libs/arm64-v8a/libshadowhook.a
include $(PREBUILT_STATIC_LIBRARY)

include $(CLEAR_VARS)
LOCAL_MODULE := libsimple
LOCAL_SRC_FILES :=main.c
LOCAL_STATIC_LIBRARIES := libcxx shadowhook
LOCAL_LDLIBS := -llog
LOCAL_C_INCLUDES := $(LOCAL_PATH)/xdl/include
LOCAL_EXPORT_C_INCLUDE_DIRS := $(LOCAL_PATH)/xdl/include
include $(BUILD_SHARED_LIBRARY)

include jni/libcxx/Android.mk
# include $(CLEAR_VARS)
# LOCAL_MODULE := example
# LOCAL_SRC_FILES := example.cpp
# LOCAL_LDLIBS := -llog -lstdc++
# include $(BUILD_SHARED_LIBRARY)