#include <stdio.h>
#include "log.h"

void onLoad(const char *process, void* api) {
    LOGD("I am in %s", process);
}