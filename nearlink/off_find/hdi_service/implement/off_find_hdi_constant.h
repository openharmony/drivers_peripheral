/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
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

#ifndef OHOS_HDI_NEARLINK_OFF_FIND_CONSTANT_H
#define OHOS_HDI_NEARLINK_OFF_FIND_CONSTANT_H

#include <string>

#include <sched.h>

namespace OHOS {
namespace HDI {
namespace Nearlink {
namespace OffFind {
constexpr const char *OFF_FIND_VENDOR_NAME = "liboff_find_vendor";
constexpr const char *SLE_OFF_FIND_CHIP_TYPE = "const.nearlink.off_find.slechiptype";
constexpr const char *OFF_FIND_VENDOR_INTERFACE_SYMBOL_NAME = "NEARLINK_OFF_FIND_VENDOR_LIB_INTERFACE";
constexpr const char *OFF_FIND_VENDOR_COMMON_NAME = "liboff_find_vendor_common_ext.z.so";
constexpr const char *OFF_FIND_VENDOR_COMMON_INTERFACE_SYMBOL_NAME = "NEARLINK_OFF_FIND_VENDOR_COMMON_LIB_INTERFACE";
constexpr int SLE_THREAD_POLICY = SCHED_RR;
constexpr int SLE_THREAD_PRIORITY = 1;
/**
 * Define OFF FIND MODEL ENABLE OR DISABLE RESULT.
 */
typedef enum {
    SUCCESS,        // HCI Command channel
    INITIALIZATION_ERROR,        // HCI Event channel
} OffFindSwitchResult;

typedef enum {
    OFF_FIND_SUCCESS,
    OFF_FIND_FAIL,
    OFF_FIND_SYNC_FAIL,
} OffFindErrorCode;

/**
 * Define POWER MODE CMD.
 */
typedef enum {
    CLEAR_RESERVED_POWER,
    SET_RESERVED_POWER
} PmuPowerMode;

/**
 * Define off find capability.
 */
typedef enum {
    OF_SLE_ADV_ENABLE = 0x01,
    OF_SLE_RING_SUPPORT = 0X02,
} OfSleFeatureFlag;

}  // namespace OffFind
}  // namespace Nearlink
}  // namespace HDI
}  // namespace OHOS

#endif /* OHOS_HDI_NEARLINK_OFF_FIND_CONSTANT_H */