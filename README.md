# zygisk-module-frida

Magisk的模块，做了两件事
- 可以指定应用注入frida的so文件
- 可以指定应用hook SSL_CTX_new获取SSL的随机字符串，用于解码tcpdump抓的https包，只hook了libjavacrypto.so，所以只对java层有效
- 可以加载指定位置的so文件
- 
zygisk-module使用的v4的api

使用的话，需要一个rule.rx文件放到`/data/local/tmp/rule.rx`
```
^com.android.browser$ frida
^com.tence ssl
^com.android.browser$ load:/data/local/tmp/hk.so
```
frida 标记代表注入libget.so

ssl 代表拦截SSL_CTX_new获取SSL的随机字符串

^com.android.browser$ 表示严格匹配com.android.browser，才进行注入

对于frida标记，还需要一个libgadget.config.so文件放到`/data/local/tmp/libgadget.config.so`
```
{
  "interaction": {
    "type": "script",
    "on_change": "reload",
    "path": "/data/local/tmp/script.js"
  }
}

```
指明加载/data/local/tmp/script.js，当前使用frida的是基于16.0.10编译的

load:/data/local/tmp/xxx.so 表示加载/data/local/tmp/xxx.so文件，该文件需要有777权限,同时需要设置`setenforce 0`

对于加载so文件，使用了xdl的代码来加载，该动态库需要实现一个onLoad函数，样例见simplelib
```
void onLoad(const char *process, void* api)
```
