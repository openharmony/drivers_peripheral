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

#include "scsitestunitready_fuzzer.h"
#include <cstring>
#include <securec.h>
#include <scsi/sg.h>
#include "hdf_log.h"
#include "scsicommonfunction_fuzzer.h"

using namespace OHOS::HDI::Usb::ScsiDdk::V1_0;

namespace OHOS {
namespace SCSI {
static void ConstructParamsFromData(ScsiPeripheralTestUnitReadyRequest& request, const uint8_t* data, size_t size)
{
    if (data == nullptr || size < sizeof(uint8_t)) {
        return;
    }

    request.control = *data;
    size_t offset = sizeof(uint8_t);
    if (size >= offset + sizeof(uint32_t)) {
        (void)memcpy_s(&request.timeout, sizeof(uint32_t), data + offset, sizeof(uint32_t));
    }
}

bool ScsiTestUnitReadyFuzzTest(const uint8_t *data, size_t size)
{
    sptr<IScsiPeripheralDdk> scsiPeripheralDdk = IScsiPeripheralDdk::Get();
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
    ScsiPeripheralTestUnitReadyRequest request = {};
    ConstructParamsFromData(request, data, size);
    ScsiPeripheralResponse response;
    ret = scsiPeripheralDdk->TestUnitReady(device, request, response);

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
    OHOS::SCSI::ScsiTestUnitReadyFuzzTest(data, size);
    return 0;
}