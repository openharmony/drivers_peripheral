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

#ifndef OHOS_HDI_INPUT_V1_0_INPUTINTERFACEIMPL_H
#define OHOS_HDI_INPUT_V1_0_INPUTINTERFACEIMPL_H

#include "input_manager.h"
#include "v1_0/iinput_interfaces.h"

namespace OHOS {
namespace HDI {
namespace Input {
namespace V1_0 {
class InputInterfacesImpl : public IInputInterfaces {
public:
    InputInterfacesImpl(): inputInterface_(NULL) {}
    virtual ~InputInterfacesImpl()
    {
        ReleaseInputInterface(inputInterface_);
    }
    void Init();
    int32_t ScanInputDevice(std::vector<DevDesc> &staArr) override;
    int32_t OpenInputDevice(uint32_t devIndex) override;
    int32_t CloseInputDevice(uint32_t devIndex) override;
    int32_t GetInputDevice(uint32_t devIndex, DeviceInfo &devInfo) override;
    int32_t GetInputDeviceList(uint32_t &devNum, std::vector<DeviceInfo> &devList, uint32_t size) override;
    int32_t SetPowerStatus(uint32_t devIndex, uint32_t status) override;
    int32_t GetPowerStatus(uint32_t devIndex, uint32_t &status) override;
    int32_t GetDeviceType(uint32_t devIndex, uint32_t &deviceType) override;
    int32_t GetChipInfo(uint32_t devIndex, std::string &chipInfo) override;
    int32_t GetVendorName(uint32_t devIndex, std::string &vendorName) override;
    int32_t GetChipName(uint32_t devIndex, std::string &chipName) override;
    int32_t SetGestureMode(uint32_t devIndex, uint32_t gestureMode) override;
    int32_t RunCapacitanceTest(uint32_t devIndex, uint32_t testType, std::string &result,
        uint32_t length) override;
    int32_t RunExtraCommand(uint32_t devIndex, const ExtraCmd &cmd) override;
    int32_t RegisterReportCallback(uint32_t devIndex, const sptr<IInputCallback> &eventPkgCallback) override;
    int32_t UnregisterReportCallback(uint32_t devIndex) override;
    int32_t RegisterHotPlugCallback(const sptr<IInputCallback> &hotPlugCallback) override;
    int32_t UnregisterHotPlugCallback() override;
private:
    IInputInterface *inputInterface_;
};
} // V1_0
} // Input
} // HDI
} // OHOS

#endif // OHOS_HDI_INPUT_V1_0_INPUTINTERFACEIMPL_H