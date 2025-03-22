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

#include "scsisendrequestbycdb_fuzzer.h"
#include <scsi/sg.h>
#include "hdf_log.h"
#include "scsicommonfunction_fuzzer.h"

using namespace OHOS::HDI::Usb::ScsiDdk::V1_0;

namespace OHOS {
namespace SCSI {

constexpr uint32_t TIMEOUT = 5000;

bool ScsiSendRequestByCDBFuzzTest(const uint8_t *data, size_t size)
{
    sptr<IScsiPeripheralDdk> scsiPeripheralDdk = IScsiPeripheralDdk::Get();
    if (scsiPeripheralDdk == nullptr) {
        HDF_LOGE("%{public}s: get ddk failed", __func__);
        return false;
    }
    int32_t ret = scsiPeripheralDdk->Init();
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: init failed, ret = %{public}d", __func__, ret);
        return false;
    }

    ScsiPeripheralDevice device;
    ret = ScsiFuzzTestHostModeInit(scsiPeripheralDdk, device);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: scsi peripheral open device failed, ret = %{public}d", __func__, ret);
        return false;
    }

    ScsiPeripheralRequest request = {};
    if (size > 0) {
        request.commandDescriptorBlock.assign(data, data + size);
    }
    request.dataTransferDirection = SG_DXFER_NONE;
    request.memMapSize = size;
    request.timeout = TIMEOUT;

    ScsiPeripheralResponse response;
    ret = scsiPeripheralDdk->SendRequestByCDB(device, request, response);

    ret = scsiPeripheralDdk->Close(device);
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: close device failed", __func__);
        scsiPeripheralDdk->Release();
        return false;
    }
    ret = scsiPeripheralDdk->Release();
    if (ret != HDF_SUCCESS) {
        HDF_LOGE("%{public}s: release failed", __func__);
        return false;
    }
    return true;
}
} // namespace SCSI
} // namespace OHOS

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    OHOS::SCSI::ScsiSendRequestByCDBFuzzTest(data, size);
    return 0;
}