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
#include <csignal>
#include <cstdlib>
#include <hdf_base.h>
#include <hdf_log.h>
#include "system_ability_definition.h"
#include "system_ability_load_callback_stub.h"

#define HDF_PROCESS_STACK_SIZE 100000
#define SLEEP_DELAY  100
#define CHECK_CNT    20
#define CHECK_TIME    30

namespace OHOS {
namespace HDI {
namespace Usb {
namespace V1_0 {
class OnDemandLoadCallback : public SystemAbilityLoadCallbackStub {
public:
    static bool loading_;
    explicit OnDemandLoadCallback();

    void OnLoadSystemAbilitySuccess(int32_t systemAbilityId, const sptr<IRemoteObject>& remoteObject);
    void OnLoadSystemAbilityFail(int32_t systemAbilityId);
private:
};

class UsbdLoadUsbService {
public:
    UsbdLoadUsbService() = default;
    ~UsbdLoadUsbService() = default;
    static int32_t LoadUsbService();
    static int32_t RemoveUsbService();
    static void SetUsbLoadRemoveCount(uint32_t count);
    static uint32_t GetUsbLoadRemoveCount();
    static void CloseUsbService();
private:
    static void IncreaseUsbLoadRemoveCount();
    static void DecreaseUsbLoadRemoveCount();
    static int32_t UsbLoadWorkEntry(void *para);
    static int32_t StartThreadUsbLoad();
    static void UsbRemoveWorkEntry(int32_t sig);
    static bool alarmRunning_;
    static uint32_t count_;
};
} // namespace V1_0
} // namespace Usb
} // namespace HDI
} // namespace OHOS

#endif
