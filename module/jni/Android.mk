LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
LOCAL_MODULE := main
LOCAL_SRC_FILES :=func.cpp main.cpp xdl/xdl.c xdl/xdl_iterate.c xdl/xdl_linker.c xdl/xdl_lzma.c xdl/xdl_util.c
LOCAL_STATIC_LIBRARIES := libcxx
LOCAL_LDLIBS := -llog
LOCAL_C_INCLUDES := $(LOCAL_PATH)/xdl/include
LOCAL_EXPORT_C_INCLUDE_DIRS := $(LOCAL_PATH)/xdl/include
include $(BUILD_SHARED_LIBRARY)

include jni/libcxx/Android.mk

# If you do not want to use libc++, link to system stdc++
# so that you can at least call the new operator in your code

# include $(CLEAR_VARS)
# LOCAL_MODULE := example
# LOCAL_SRC_FILES := example.cpp
# LOCAL_LDLIBS := -llog -lstdc++
# include $(BUILD_SHARED_LIBRARY)
