/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "scsicommonfunction_fuzzer.h"
#include "UsbSubscriberTest.h"
#include "hdf_log.h"
#define HDF_LOG_TAG scsi_ddk_fuzzer

using namespace OHOS::HDI::Usb::ScsiDdk::V1_0;

namespace OHOS {
namespace SCSI {

constexpr uint32_t SHIFT_32 = 32;
uint64_t interfaceIndex = 0x00;
constexpr uint32_t DEVICE_MEM_MAP_SIZE = 1024;

static uint64_t ToDdkDeviceId(const uint8_t busNum, const uint8_t devAddr)
{
    return ((uint64_t)busNum << SHIFT_32) + devAddr;
}

int32_t ScsiFuzzTestHostModeInit(const sptr<IScsiPeripheralDdk> &scsiPeripheralDdk, ScsiPeripheralDevice &device)
{
    sptr<OHOS::HDI::Usb::V1_0::IUsbInterface> usbInterface = OHOS::HDI::Usb::V1_0::IUsbInterface::Get();
    sleep(SLEEP_TIME);

    sptr<OHOS::USB::UsbSubscriberTest> subscriber = new OHOS::USB::UsbSubscriberTest();
    int32_t ret = usbInterface->BindUsbdSubscriber(subscriber);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: bind usbd subscriber failed", __func__);
        return ret;
    }

    uint8_t busNum = subscriber->busNum_;
    uint8_t devAddr = subscriber->devAddr_;
    uint64_t deviceId = ToDdkDeviceId(busNum, devAddr);
    HDF_LOGI("%{public}s: busNum:%{public}d, devAddr:%{public}d, deviceID:%{public}llu", __func__,
        busNum, devAddr, deviceId);
    usbInterface->UnbindUsbdSubscriber(subscriber);

    int memMapFd = -1;
    ret = scsiPeripheralDdk->Open(deviceId, interfaceIndex, device, memMapFd);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: open device failed, deviceId:%{public}llu, interfaceIndex:%{public}llu, ret:%{public}d",
            __func__, deviceId, interfaceIndex, ret);
    }
    ftruncate(memMapFd, DEVICE_MEM_MAP_SIZE);

    return ret;
}
} // namespace SCSI
} // namespace OHOS
