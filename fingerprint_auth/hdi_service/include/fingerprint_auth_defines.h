/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#ifndef FINGERPRINT_AUTH_DEFINES_H
#define FINGERPRINT_AUTH_DEFINES_H

namespace OHOS {
namespace HDI {
namespace FingerprintAuth {
namespace V1_0 {
enum ResultCode : int32_t {
    SUCCESS = 0,
    FAIL = 1,
    GENERAL_ERROR = 2,
    CANCELED = 3,
    TIMEOUT = 4,
    TYPE_NOT_SUPPORT = 5,
    TRUST_LEVEL_NOT_SUPPORT = 6,
    BUSY = 7,
    INVALID_PARAMETERS = 8,
    LOCKED = 9,
    NOT_ENROLLED = 10,
    OPERATION_NOT_SUPPORT = 11,
    FRAMEWORK_RESULT_CODE_MAX,
    VENDOR_RESULT_CODE_BEGIN = 10000,
};
} // namespace V1_0
} // namespace FingerprintAuth
} // namespace HDI
} // namespace OHOS
#endif  // FINGERPRINT_AUTH_DEFINES_H
