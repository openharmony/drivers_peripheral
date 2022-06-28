/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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

#include "adaptor_time.h"

#include <time.h>
#include "adaptor_log.h"

#define MS_OF_S 1000
#define NS_OF_MS 1000000

uint64_t GetRtcTime(void)
{
    struct timespec curTime;
    int res = clock_gettime(CLOCK_MONOTONIC, &curTime);
    if (res != 0) {
        LOG_ERROR("get time fail");
        return 0;
    }
    return curTime.tv_sec * MS_OF_S + curTime.tv_nsec / NS_OF_MS;
}

uint64_t GetSystemTime(void)
{
    struct timespec curTime;
    int res = clock_gettime(CLOCK_MONOTONIC, &curTime);
    if (res != 0) {
        LOG_ERROR("get time fail");
        return 0;
    }
    return curTime.tv_sec * MS_OF_S + curTime.tv_nsec / NS_OF_MS;
}