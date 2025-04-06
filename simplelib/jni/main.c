#include <stdio.h>
#include <string.h>
#include <android/log.h>
#include "../shadowhook/include/shadowhook.h"
#include "xdl/include/xdl.h"

#define LOG_TAG "SIMP"
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)


struct HookInfo {
    void* origAddr;
    void* stubAddr;
    void * funcAddr;
    void *replaceFucAddr;
    const char* name;
};

struct HookInfo hooks[5] = {0};

struct HookInfo* find_by_name(const char*name) {
    for(int i = 0; i < 5; i++) {
        if(hooks[i].name == NULL) {
            break;
        }
        if(strcmp(name, hooks[i].name) == 0) {
            return hooks + i;
        }
    }
    return NULL;
}

typedef int (*__SSL_op)(void *ssl, const void *buf, int num);

typedef void* (*__SSL_CTX_new)(const void *method);

static void (*__SSL_CTX_set_keylog_callback)(void *ctx,
                                             void (*cb)(const void *ssl,
                                                        const char *line));
void sslkeylog_callback(const void *ssl, const char *line) {
    LOGD("sk:%s\n", line);
}

int _SSL_write(void *ssl, const void *buf, int num) {
    LOGD("SSL_write:%s\n", buf);
    struct HookInfo* hk = find_by_name("SSL_write");
    return ((__SSL_op )hk->origAddr)(ssl, buf, num);
}
int _SSL_read(void *ssl, const void *buf, int num) {
    LOGD("SSL_read:%s\n", buf);
    struct HookInfo* hk = find_by_name("SSL_read");
    return ((__SSL_op )hk->origAddr)(ssl, buf, num);
}

void* _SSL_CTX_new(const void *method)
{
    struct HookInfo* hk = find_by_name("SSL_CTX_new");
    void* ctx = ((__SSL_CTX_new)hk->origAddr)(method);
    if(__SSL_CTX_set_keylog_callback) {
        __SSL_CTX_set_keylog_callback(ctx, sslkeylog_callback);
    }
    return ctx;
}

void setup_hook() {
    hooks[0].name = "SSL_CTX_new";
    hooks[0].replaceFucAddr = (void*)_SSL_CTX_new;
    hooks[1].name = "SSL_write";
    hooks[1].replaceFucAddr = (void*)_SSL_write;
    hooks[1].name = "SSL_read";
    hooks[1].replaceFucAddr = (void*)_SSL_read;
}

int add_hook(const char* name, void* func) {
    struct HookInfo* hk = find_by_name(name);
    if(hk == NULL) {
        LOGD("hook error cannot find hook info %s", name);
        return -1;
    }
    void* stub = shadowhook_hook_func_addr(func, hk->replaceFucAddr, &hk->origAddr);
    if(stub == NULL)
    {
        int error_num = shadowhook_get_errno();
        const char *error_msg = shadowhook_to_errmsg(error_num);
        LOGD("hook error %d - %s", error_num, error_msg);
        return -1;
    }
    hk->stubAddr = stub;
    return 0;
}


void do_hook()
{
    void *libssl = xdl_open("libssl.so", XDL_DEFAULT);
    __SSL_CTX_set_keylog_callback = (void (*)(void *, void (*)(const void *, const char *)))xdl_sym(libssl, "SSL_CTX_set_keylog_callback",
                                                                                                    NULL);
    void* SSL_CTX_new = (void (*))xdl_sym(libssl, "SSL_CTX_new", NULL);
    void* SSL_write = (void (*))xdl_sym(libssl, "SSL_write", NULL);
    void* SSL_read = (void (*))xdl_sym(libssl, "SSL_read", NULL);
    add_hook("SSL_CTX_new",SSL_CTX_new);
    add_hook("SSL_write",SSL_write);
    add_hook("SSL_read",SSL_read);

}

void onLoad(const char *process, void* api) {
    LOGD("I am in %s", process);
    setup_hook();
    shadowhook_init(1, 1);
    do_hook();
}
