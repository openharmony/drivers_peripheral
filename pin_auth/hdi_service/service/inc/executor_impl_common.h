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

#ifndef OHOS_HDI_PIN_AUTH_EXECUTOR_COMMON_H
#define OHOS_HDI_PIN_AUTH_EXECUTOR_COMMON_H

#include "pin_auth_hdi.h"

namespace OHOS {
namespace HDI {
namespace PinAuth {
constexpr uint32_t EXECUTOR_MATCHER = 0;
constexpr uint16_t SENSOR_ID = 1;

void CallError(const sptr<HdiIExecutorCallback> &callback, uint32_t errorCode);
} // PinAuth
} // HDI
} // OHOS

#endif // OHOS_HDI_PIN_AUTH_EXECUTOR_COMMON_H
