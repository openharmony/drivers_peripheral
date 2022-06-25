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

#ifndef COMMON_DEFINES_H
#define COMMON_DEFINES_H

#include "stdint.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum ResultCode {
    RESULT_SUCCESS = 0x0,
    RESULT_GENERAL_ERROR = 0x1,
    RESULT_BAD_PARAM = 0x2,
    RESULT_BAD_COPY = 0x3,
    RESULT_NO_MEMORY = 0x4,
    RESULT_NEED_INIT = 0x5,
    RESULT_NOT_FOUND = 0x6,
    RESULT_REACH_LIMIT = 0x7,
    RESULT_DUPLICATE_CHECK_FAILED = 0x8,
    RESULT_BAD_READ = 0x9,
    RESULT_BAD_WRITE = 0xA,
    RESULT_BAD_DEL = 0xB,
    RESULT_UNKNOWN = 0xC,
    RESULT_BAD_MATCH = 0xD,
    RESULT_BAD_SIGN = 0xE,
    RESULT_BUSY = 0xF,
    RESULT_TOKEN_TIMEOUT = 0x10,
    RESULT_VERIFY_TOKEN_FAIL = 0x11,
    RESULT_EXCEED_LIMIT = 0x12,
    RESULT_IDM_SESSION_TIMEOUT = 0x13,

    RESULT_AUTH_NOT_COMPELETED = 0x10001,
} ResultCode;

typedef enum AuthType {
    DEFAULT_AUTH_TYPE = 0,
    PIN_AUTH = 1,
    FACE_AUTH = 2,
    FINGER_AUTH = 4,
} AuthType;

typedef enum ScheduleMode {
    SCHEDULE_MODE_ENROLL = 0,
    SCHEDULE_MODE_AUTH = 1,
    SCHEDULE_MODE_IDENTIFY = 2,
} ScheduleMode;

typedef enum AuthSubType {
    DEFAULT_TYPE = 0,
} AuthSubType;

typedef struct TemplateIdArrays {
    uint64_t *value;
    uint32_t num;
} TemplateIdArrays;

typedef enum AuthPropertyMode {
    PROPERMODE_DELETE = 0,
    PROPERMODE_GET = 1,
    PROPERMODE_SET = 2,
    PROPERMODE_LOCK = 3,
    PROPERMODE_UNLOCK = 4,
    PROPERMODE_INIT_ALGORITHM = 5,
    PROPERMODE_RELEASE_ALGORITHM = 6,
    PROPERMODE_SET_SURFACE_ID = 100,
} AuthPropertyMode;

#define MAX_DUPLICATE_CHECK 100
#define INVALID_SENSOR_HINT 0
#define MAX_TEMPLATE_OF_SCHEDULE 10

#ifdef __cplusplus
}
#endif

#endif
