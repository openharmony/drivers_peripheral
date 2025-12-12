/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <dlfcn.h>
#include <limits.h>
#include <pthread.h>
#include <securec.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "hdf_sbuf.h"

typedef void (*AudioIpcTestInitFunc)();

int32_t main(int32_t argc, char const *argv[])
{
    struct HdfSBuf *sbuf = HdfSbufObtain(128);
    if (sbuf == NULL) {
        printf("Failed to obtain HdfSBuf");
        return -1;
    }
    void* handle = dlopen("libaudio_ipc_test.z.so", RTLD_LAZY);
    if (handle == NULL) {
        printf("dlopen libaudio_ipc_test.z.so failed");
        return 1;
    }
    AudioIpcTestInitFunc ipcFunc = dlsym(handle, "AudioIpcTestInitFunc");
    if (ipcFunc == NULL) {
        printf("dlsym AudioIpcTestInitFunc failed\n");
        return 1;
    }
    ipcFunc();
    dlclose(handle);
    return 0;
}