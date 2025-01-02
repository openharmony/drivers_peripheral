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

#include <cstddef>
#include <cstdint>
#include <unistd.h>

#include "UsbSubscriberTest.h"
#include "hdf_log.h"
#include "usbasynctransfer_fuzzer.h"
#include "v1_2/iusb_interface.h"

using namespace OHOS::HDI::Usb::V1_2;
using OHOS::HDI::Usb::V1_2::UsbDev;
using namespace OHOS::USB;

namespace OHOS {
constexpr int32_t ASHMEM_MAX_SIZE = 1024;
constexpr int32_t BITS_PER_BYTE = 8;
constexpr int32_t ASYNC_TRANSFER_TIME_OUT = 1000;
constexpr int32_t LIBUSB_TRANSFER_TYPE_BULK = 2;
constexpr int32_t NUM_THREE = 3;
constexpr int32_t NUM_TWO = 2;
constexpr int32_t NUM_ONE = 1;

uint32_t Convert2Uint32(const uint8_t *ptr)
{
    if (ptr == nullptr) {
        return 0;
    }
    /*
     * Move the 0th digit 24 to the left, the first digit 16 to the left, the second digit 8 to the left,
     * and the third digit no left
     */
    return (ptr[0] << BITS_PER_BYTE * NUM_THREE) | (ptr[NUM_ONE] << BITS_PER_BYTE * NUM_TWO) |
        (ptr[NUM_TWO] << BITS_PER_BYTE) | (ptr[NUM_THREE]);
}

int32_t InitAshmemOne(sptr<Ashmem> &asmptr, int32_t asmSize, uint8_t rflg)
{
    asmptr = Ashmem::CreateAshmem("ttashmem000", asmSize);
    if (asmptr == nullptr) {
        HDF_LOGE("InitAshmemOne CreateAshmem failed");
        return HDF_FAILURE;
    }

    asmptr->MapReadAndWriteAshmem();

    if (rflg == 0) {
        uint8_t tdata[ASHMEM_MAX_SIZE];
        int32_t offset = 0;
        int32_t tlen = 0;

        int32_t retSafe = memset_s(tdata, sizeof(tdata), 'Y', ASHMEM_MAX_SIZE);
        if (retSafe != EOK) {
            HDF_LOGE("InitAshmemOne memset_s failed");
            return HDF_FAILURE;
        }
        while (offset < asmSize) {
            tlen = (asmSize - offset) < ASHMEM_MAX_SIZE ? (asmSize - offset) : ASHMEM_MAX_SIZE;
            asmptr->WriteToAshmem(tdata, tlen, offset);
            offset += tlen;
        }
    }
    return HDF_SUCCESS;
}

bool DoSomethingInterestingWithMyAPI(const uint8_t *rawData, size_t size)
{
    if (rawData == nullptr) {
        return false;
    }
    uint32_t asmSize = Convert2Uint32(rawData);
    sptr<OHOS::HDI::Usb::V1_2::IUsbInterface> usbInterface = OHOS::HDI::Usb::V1_2::IUsbInterface::Get(false);
    if (usbInterface == nullptr) {
        HDF_LOGE("%{public}s:IUsbInterface::Get() failed.", __func__);
        return false;
    }
    sptr<UsbSubscriberTest> subscriber = new UsbSubscriberTest();
    int32_t ret = usbInterface->BindUsbdSubscriber(subscriber);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: bind usbd subscriber failed", __func__);
        return ret;
    }
    sleep(1);
    UsbDev dev;
    dev.busNum = subscriber->busNum_;
    dev.devAddr = subscriber->devAddr_;
    ret = usbInterface->OpenDevice(dev);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: open device failed", __func__);
        return ret;
    }
    USBTransferInfo usbInfo_;
    usbInfo_.endpoint = 0x1;
    usbInfo_.flags = 0;
    usbInfo_.type = LIBUSB_TRANSFER_TYPE_BULK;
    usbInfo_.timeOut = ASYNC_TRANSFER_TIME_OUT;
    usbInfo_.userData = 0;
    usbInfo_.numIsoPackets = 0;
    usbInfo_.length = 0;
    sptr<Ashmem> ashmPtr;
    (void)InitAshmemOne(ashmPtr, asmSize, 0);
    usbInterface->UsbSubmitTransfer(dev, usbInfo_, nullptr, ashmPtr);

    return true;
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    OHOS::DoSomethingInterestingWithMyAPI(data, size);
    return 0;
}
