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

#ifndef USBSUBSCRIBERTEST_H
#define USBSUBSCRIBERTEST_H

#include "usbd_subscriber.h"

namespace OHOS {
namespace USB {
class UsbSubscriberTest : public UsbdSubscriber {
public:
    UsbSubscriberTest() = default;
    ~UsbSubscriberTest() = default;
    int32_t DeviceEvent(const UsbInfo &info) override;
    int32_t PortChangedEvent(int32_t portId, int32_t powerRole, int32_t dataRole, int32_t mode) override
    {
        return 0;
    };

    int32_t busNum_;
    int32_t devAddr_;
};
} // namespace USB
} // namespace OHOS

#endif