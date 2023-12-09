/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "sensor_client_info.h"

namespace OHOS {
namespace HDI {
namespace Sensor {
namespace V1_1 {

SensorClientInfo::SensorClientInfo()
{
}

SensorClientInfo::~SensorClientInfo()
{
}

void SensorClientInfo::SetReportDataCb(const sptr<ISensorCallback> &callbackObj)
{
    pollCallback_ = callbackObj;
}

sptr<ISensorCallback> SensorClientInfo::GetReportDataCb()
{
    return pollCallback_;
}

} // V1_1
} // Sensor
} // HDI
} // OHOS