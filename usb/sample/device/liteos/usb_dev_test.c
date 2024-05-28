/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include <stdio.h>
#include <string.h>
#include "hdf_base.h"
#include "hdf_log.h"
#include "usb_dev_test.h"

#define OPTION_LENGTH 2

static void ShowUsage(void)
{
    printf("Usage options:\n");
    printf("-1 : AcmTest\n");
    printf("-2 : PropTest\n");
    printf("-3 : AcmSpeedRead\n");
    printf("-4 : AcmSpeedWrite\n");
    printf("-h : show usage\n");
}

int32_t main(int32_t argc, char *argv[])
{
    if (argc < OPTION_LENGTH) {
        printf("argv too flew\n");
        HDF_LOGE("%{public}s:%{public}d argc=%{public}d is too flew!", __func__, __LINE__, argc);
        return -1;
    }
    const char **arg = (const char **)&argv[1];
    if (strcmp(arg[0], "-1") == 0) {
        AcmTest(argc - 1, arg);
    } else if (strcmp(arg[0], "-2") == 0) {
        PropTest(argc - 1, arg);
    } else if (strcmp(arg[0], "-3") == 0) {
        AcmSpeedRead(argc - 1, arg);
    } else if (strcmp(arg[0], "-4") == 0) {
        AcmSpeedWrite(argc - 1, arg);
    } else if (strcmp(arg[0], "-h") == 0 || \
        strcmp(arg[0], "?") == 0) {
        ShowUsage();
    } else {
        printf("unknown cmd\n");
    }
    return 0;
}
