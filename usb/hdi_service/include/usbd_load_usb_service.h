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

#ifndef USBD_LOAD_USB_SERVICE_H
#define USBD_LOAD_USB_SERVICE_H
#include <atomic>
#include <csignal>
#include <cstdlib>
#include <hdf_base.h>
#include <hdf_log.h>
#include <sys/time.h>

#include "system_ability_definition.h"
#include "system_ability_load_callback_stub.h"

namespace OHOS {
namespace HDI {
namespace Usb {
namespace V1_2 {
class OnDemandLoadCallback : public SystemAbilityLoadCallbackStub {
public:
    std::atomic_bool loading_ {false};
    explicit OnDemandLoadCallback();
    ~OnDemandLoadCallback();
    void OnLoadSystemAbilitySuccess(int32_t systemAbilityId, const sptr<IRemoteObject> &remoteObject);
    void OnLoadSystemAbilityFail(int32_t systemAbilityId);

private:
};

class UsbdLoadService {
public:
    UsbdLoadService(int32_t saId);
    ~UsbdLoadService();
    int32_t LoadService();

private:
    sptr<OnDemandLoadCallback> loadCallback_ {nullptr};
    int32_t saId_ {0};
};
} // namespace V1_2
} // namespace Usb
} // namespace HDI
} // namespace OHOS

#endif
