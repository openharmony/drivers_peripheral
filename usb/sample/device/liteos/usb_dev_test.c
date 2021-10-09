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

#include "usb_dev_test.h"

#define OPTION_EDN (-1)

static void ShowUsage()
{
    printf("Usage options:\n");
    printf("-1 : acm_test\n");
    printf("-2 : prop_test\n");
    printf("-3 : acm_speed_read\n");
    printf("-4 : acm_speed_write\n");
}

int main(int argc, char *argv[])
{
    int ch;
    char **arg = &argv[1];
    while ((ch = getopt(argc, argv, "1:2:3:4:h?")) != OPTION_EDN) {
        switch (ch) {
            case '1':
                acm_test(argc - 1, arg);
                break;
            case '2':
                prop_test(argc - 1, arg);
                break;
            case '3':
                acm_speed_read(argc - 1, arg);
                break;
            case '4':
                acm_speed_write(argc - 1, arg);
                break;
            case 'h':
            case '?':
                ShowUsage();
                return 0;
                break;
            default:
                break;
        }
    }
    return 0;
}
