/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef SENSOR_TRACE_H
#define SENSOR_TRACE_H

#include "hitrace_meter.h"

#define SENSOR_TRACE_TAG HITRACE_TAG_OHOS
#define SENSOR_TRACE HITRACE_METER_NAME(SENSOR_TRACE_TAG, __func__)

#define SENSOR_TRACE_PID do { \
    uint32_t serviceId = static_cast<uint32_t>(HdfRemoteGetCallingPid()); \
    std::string st = std::string(__func__) + ":pid " + std::string(serviceId); \
    HITRACE_METER_NAME(SENSOR_TRACE_TAG, st.c_str()); \
} while (0)

#define SENSOR_TRACE_MSG(msg) do { \
    std::string st = std::string(__func__) + ":" + (msg); \
    HITRACE_METER_NAME(SENSOR_TRACE_TAG, st.c_str()); \
} while (0)

#define SENSOR_TRACE_PID_MSG(msg) do { \
    uint32_t serviceId = static_cast<uint32_t>(HdfRemoteGetCallingPid()); \
    std::string st = std::string(__func__) + ":pid " + std::string(serviceId) + "," + (msg); \
    HITRACE_METER_NAME(SENSOR_TRACE_TAG, st.c_str()); \
} while (0)

#define SENSOR_TRACE_START(msg) do { \
    std::string st = std::string(__func__) + ":" + (msg); \
    StartTrace(SENSOR_TRACE_TAG, st.c_str()); \
} while (0)

#define SENSOR_TRACE_FINISH FinishTrace(SENSOR_TRACE_TAG)

#endif //SENSOR_TRACE_H
