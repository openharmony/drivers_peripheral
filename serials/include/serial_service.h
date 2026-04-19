/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#ifndef OHOS_HDI_SERIALS_V1_0_SERIAL_SERVICE_H
#define OHOS_HDI_SERIALS_V1_0_SERIAL_SERVICE_H

#include "v1_0/iserials.h"
#include "serial_device_manager.h"

namespace OHOS {
namespace HDI {
namespace Serials {
namespace V1_0 {
class SerialService : public ISerials {
public:
    SerialService();
    ~SerialService() override {}

    int32_t QueryDevices(std::vector<SerialDeviceInfo>& devices) override;

    int32_t OpenDevice(const std::string& portName, const SerialConfig& config, const sptr<ISerialDeviceCallback>& cb,
        sptr<ISerialDevice>& device) override;
};
} // V1_0
} // Serials
} // HDI
} // OHOS

#endif // OHOS_HDI_SERIALS_V1_0_SERIAL_SERVICE_H
