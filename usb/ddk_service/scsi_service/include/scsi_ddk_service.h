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

#ifndef SCSI_DDK_SERVICE_H
#define SCSI_DDK_SERVICE_H

#include "scsi_os_apdater.h"
#include "v1_0/iscsi_peripheral_ddk.h"

namespace OHOS {
namespace HDI {
namespace Usb {
namespace ScsiDdk {
namespace V1_0 {

class ScsiDdkService : public IScsiPeripheralDdk {
public:
    ScsiDdkService(std::shared_ptr<ScsiOsAdapter> &osAdapter) : osAdapter_(osAdapter) {};
    virtual ~ScsiDdkService() = default;

    int32_t Init() override;

    int32_t Release() override;

    int32_t Open(uint64_t deviceId, uint8_t interfaceIndex, ScsiPeripheralDevice& dev, int &memMapFd) override;

    int32_t Close(const ScsiPeripheralDevice& dev) override;

    int32_t ReadCapacity10(const ScsiPeripheralDevice& dev, const ScsiPeripheralReadCapacityRequest& request,
        ScsiPeripheralCapacityInfo& capacityInfo, ScsiPeripheralResponse& response) override;

    int32_t TestUnitReady(const ScsiPeripheralDevice& dev, const ScsiPeripheralTestUnitReadyRequest& request,
        ScsiPeripheralResponse& response) override;

    int32_t Inquiry(const ScsiPeripheralDevice& dev, const ScsiPeripheralInquiryRequest& request,
        ScsiPeripheralInquiryInfo& inquiryInfo, ScsiPeripheralResponse& response) override;

    int32_t RequestSense(const ScsiPeripheralDevice& dev, const ScsiPeripheralRequestSenseRequest& request,
        ScsiPeripheralResponse& response) override;

    int32_t Read10(const ScsiPeripheralDevice& dev, const ScsiPeripheralIORequest& request,
        ScsiPeripheralResponse& response) override;

    int32_t Write10(const ScsiPeripheralDevice& dev, const ScsiPeripheralIORequest& request,
        ScsiPeripheralResponse& response) override;

    int32_t Verify10(const ScsiPeripheralDevice& dev, const ScsiPeripheralVerifyRequest& request,
        ScsiPeripheralResponse& response) override;

    int32_t SendRequestByCDB(const ScsiPeripheralDevice& dev, const ScsiPeripheralRequest& request,
        ScsiPeripheralResponse& response) override;

private:
    int32_t GetDeviceMemMapFd(uint16_t busNum, uint16_t devAddr, uint8_t interfaceIndex, int &memMapFd);

    std::shared_ptr<ScsiOsAdapter> osAdapter_;
};
} // V1_0
} // ScsiDdk
} // Usb
} // HDI
} // OHOS

#endif // SCSI_DDK_SERVICE_H

