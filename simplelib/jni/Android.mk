LOCAL_PATH:= $(call my-dir)

include $(CLEAR_VARS)
LOCAL_SRC_FILES := main.c
LOCAL_MODULE := libsimple
LOCAL_MODULE_TAGS := optional
LOCAL_CFLAGS := -Werror

LOCAL_LDLIBS     := -llog

include $(BUILD_SHARED_LIBRARY)
