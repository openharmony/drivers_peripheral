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

#ifndef OHOS_HDI_SERIALS_V1_0_SERIAL_DEVICE_CALLBACK_H
#define OHOS_HDI_SERIALS_V1_0_SERIAL_DEVICE_CALLBACK_H

#include "v1_0/iserial_device_callback.h"

namespace OHOS {
namespace HDI {
namespace Serials {
namespace V1_0 {
class SerialDeviceCallback : public ISerialDeviceCallback {
public:
    SerialDeviceCallback(const sptr<ISerialDeviceCallback>& callback);
    virtual ~SerialDeviceCallback() {}

    int32_t OnDeviceOffline() override;

    int32_t OnReadData(const std::vector<int8_t>& data, uint32_t dataLen) override;

private:
    sptr<ISerialDeviceCallback> callback_;
};
} // V1_0
} // Serials
} // HDI
} // OHOS

#endif // OHOS_HDI_SERIALS_V1_0_SERIAL_DEVICE_CALLBACK_H
