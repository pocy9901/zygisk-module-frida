/* Copyright 2022-2023 John "topjohnwu" Wu
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH
 * REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT,
 * INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
 * LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR
 * OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 * PERFORMANCE OF THIS SOFTWARE.
 */

#include <cstdlib>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <dlfcn.h>

#include "xdl.h"

#include "log.h"
#include "zygisk.hpp"
#include "func.h"


using zygisk::Api;
using zygisk::AppSpecializeArgs;
using zygisk::ServerSpecializeArgs;


void sslkeylog_callback(const void *ssl, const char *line) {
    LOGD("sk:%s\n", line);
}
static void * (*__SSL_CTX_new)(const void *method);
static void (*__SSL_CTX_set_keylog_callback)(void *ctx,
                                        void (*cb)(const void *ssl,
                                                   const char *line));
static void *_SSL_CTX_new(const void *method) {
    LOGD("_SSL_CTX_new\n");
    void * ret = __SSL_CTX_new(method);
    __SSL_CTX_set_keylog_callback(ret, sslkeylog_callback);
    return ret;
}


static int match_rule(const char * match_content, char * rules, int size, char *type) {
    int len = strlen(match_content);
    char * token = rules;
    char * end = rules + size;
    char * token_end;
    char * line = NULL;
    char * line_end = NULL;
    int match_token = 0;
    int go = 0;
    while(token < end) {
        line = read_line(token, end, &line_end);
        if(line == NULL) break;
        if(line[0] == '#') {
            token = line_end + 1;
            continue;
        }
        token = next_token(token, line_end, &token_end);
        if(token == NULL) break;
        if(*token == '!') {
            token ++;
            int mc = match(token, token_end, match_content, match_content + len);
            if(mc) {
                go = 0;
                break;
            }
        } else {
            int mc = match(token, token_end, match_content, match_content + len);
            if(mc) {
                if(type != NULL) {
                    char *type_token = next_token(token_end + 1, line_end, &token_end);
                    if(type_token == NULL) {
                        *type = 0;
                    } else {
                        while(type_token < token_end) {
                            *(type++) = *(type_token++);
                        }
                        *type = 0;
                    }
                }
                go = 1;
                break;
            }
        }
        token = line_end + 1;
    }
    return go;
}

class MyModule : public zygisk::ModuleBase {
public:
    void onLoad(Api *api, JNIEnv *env) override {
        this->api = api;
        this->env = env;
        this->rule_content = NULL;
        this->rule_size = 0;
    }

    void preAppSpecialize(AppSpecializeArgs *args) override {
        // Use JNI to fetch our process name
        const char *process = env->GetStringUTFChars(args->nice_name, nullptr);
        preSpecialize(process);
        env->ReleaseStringUTFChars(args->nice_name, process);
    }

    /**
     * user space to load so
     * @param args
     */
    void postAppSpecialize(const AppSpecializeArgs *args) override {
        const char *process = env->GetStringUTFChars(args->nice_name, nullptr);
        int size = this->rule_size;
        char * rules = this->rule_content;
        if(rules != NULL) {
            const char * match_content = process;
            char type[512] = {0};
            int go = match_rule(match_content, rules, size, type);
            free(rules);
            this->rule_content = NULL;
            pid_t  pid = getpid();

            LOGD("(%s) postAppSpecialize match %d\n", process, go);
            if(go) {
                if(strstr(type, "ssl") == type) {// hook ssl
                    dev_t  dev;
                    ino_t ino;
                    if(get_module_devinfo("libjavacrypto.so", pid, &dev, &ino) > 0) {
                        void *libssl = xdl_open("libssl.so", XDL_DEFAULT);
                        __SSL_CTX_set_keylog_callback = (void (*)(void *, void (*)(const void *, const char *)))xdl_sym(libssl, "SSL_CTX_set_keylog_callback",
                                                                                                                        nullptr);
                        LOGD("__SSL_CTX_set_keylog_callback %lx", (unsigned long)__SSL_CTX_set_keylog_callback);

                        api->pltHookRegister(dev, ino, "SSL_CTX_new", (void *)_SSL_CTX_new, (void **)&__SSL_CTX_new);
                        if(api->pltHookCommit()) {
                            LOGD("pltHookCommit OK in %s", process);
                        } else {
                            LOGD("pltHookCommit ERROR in %s", process);
                        }

                    } else {
                        LOGD("get_module_devinfo ERROR in %s", process);
                    }

                    LOGD("(%s) %lx %lx find ssl\n", process, (unsigned long)__SSL_CTX_set_keylog_callback, (unsigned long)__SSL_CTX_new);
                }
                if(strstr(type, "frida") == type) {// load frida.so
                    void *frida = xdl_open("libget.so", XDL_TRY_FORCE_LOAD);
                    if(NULL == frida) {
                        LOGD("(%s) load frida-gadget failed %s\n", process, dlerror());
                    } else {
                        LOGD("(%s) load frida-gadget success\n", process);
                    }
                }
                if(strstr(type, "load:") == type) {// load xx.so
                    char * sofile = type + 5;
                    void *soload = xdl_open(sofile, XDL_TRY_FORCE_LOAD);
                    if(NULL == soload) {
                        LOGD("(%s) load %s failed %s\n", process, sofile, dlerror());
                    } else {
                        typedef void *(*onLoad)(const char *, void *);
                        LOGD("(%s) load %s success\n", process, sofile);
                        onLoad  onloadFunc = (onLoad)xdl_sym(soload, "onLoad",nullptr);
                        if(onloadFunc != nullptr) {
                            onloadFunc(process, api);
                        }
                    }
                }
            }
        }
        env->ReleaseStringUTFChars(args->nice_name, process);
    }

private:
    Api *api;
    JNIEnv *env;

    char * rule_content;
    int rule_size;

    void preSpecialize(const char *process) {
        // Demonstrate connecting to to companion process
        // read rule content
        int size = 0;
        char * rules = NULL;

        int fd = api->connectCompanion();
        read(fd, &size, sizeof(size));
        if(size > 0) {
            rules = (char *)malloc(size+1);
            read(fd, rules, size);
            rules[size] = 0;
        }
        close(fd);
        pid_t  pid = getpid();
        //LOGD("preAppSpecialize in %s %d", process, pid);
        if(rules != NULL) {
            const char * match_content = process;
            char type[512] = {0};
            int go = match_rule(match_content, rules, size, type);
            if(go) {
                LOGD("matched in %s %d", process, pid);
                this->rule_content = rules;
                this->rule_size = size;
            } else {
                free(rules);
                api->setOption(zygisk::Option::DLCLOSE_MODULE_LIBRARY);
            }
        } else {
            LOGD("read rule error in %s", process);
            api->setOption(zygisk::Option::DLCLOSE_MODULE_LIBRARY);
        }
    }

};


static void companion_handler(int i) {
    int size;
    char * rules = read_content("/data/local/tmp/rule.rx", &size);
    write(i, &size, sizeof(size));
    if(rules != NULL) {
        write(i, rules, size);
        free(rules);
    }
}

// Register our module class and the companion handler function
REGISTER_ZYGISK_MODULE(MyModule)
REGISTER_ZYGISK_COMPANION(companion_handler)
