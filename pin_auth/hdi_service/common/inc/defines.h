/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

#define IF_TRUE_LOGE_AND_RETURN_VAL(cond, retVal) \
    do { \
        if (cond) { \
            LOG_ERROR("(" #cond ") check fail, return"); \
            return (retVal); \
        } \
    } while (0)

#define IF_TRUE_LOGE_AND_RETURN(cond) \
    do { \
        if (cond) { \
            LOG_ERROR("(" #cond ") check fail, return"); \
            return; \
        } \
    } while (0)

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
    RESULT_PIN_FREEZE = 0x11,
    RESULT_PIN_FAIL = 0X12,
    RESULT_COMPARE_FAIL = 0x13
} ResultCode;

typedef enum ResultCodeForCoAuth {
    /**
     * Indicates that authentication is success or ability is supported.
     */
    SUCCESS = 0,

    /**
     * Indicates the authenticator fails to identify user.
     */
    FAIL = 1,

    /**
     * Indicates other errors.
     */
    GENERAL_ERROR = 2,

    /**
     * Indicates that authentication has been canceled.
     */
    CANCELED = 3,

    /**
     * Indicates that authentication has timed out.
     */
    TIMEOUT = 4,

    /**
     * Indicates that this authentication type is not supported.
     */
    TYPE_NOT_SUPPORT = 5,

    /**
     * Indicates that the authentication trust level is not supported.
     */
    TRUST_LEVEL_NOT_SUPPORT = 6,

    /**
     * Indicates that the authentication task is busy. Wait for a few seconds and try again.
     */
    BUSY = 7,

    /**
     * Indicates incorrect parameters.
     */
    INVALID_PARAMETERS = 8,

    /**
     * Indicates that the authenticator is locked.
     */
    LOCKED = 9,

    /**
     * Indicates that the user has not enrolled the authenticator.
     */
    NOT_ENROLLED = 10,
} ResultCodeForCoAuth;

typedef enum AuthType {
    DEFAULT_AUTH_TYPE = 0,
    PIN_AUTH = 1,
    FACE_AUTH = 2,
} AuthType;

typedef enum AuthSubType {
    DEFAULT_TYPE = 0,
} AuthSubType;

typedef enum {
    DEDAULT = 0,
    ABANDONED_PIN_AUTH = 4,
} AuthInent;

#define MAX_DULPLICATE_CHECK 100

#define MAX_EXECUTOR_MSG_LEN 2048

#define ROOT_SECRET_LEN 32U

#ifdef __cplusplus
}
#endif // __cplusplus
#endif // COMMON_DEFINES_H
