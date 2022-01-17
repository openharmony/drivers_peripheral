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

#ifndef HDI_THERMAL_V1_0_THERMALINTERFACESERVICE_H
#define HDI_THERMAL_V1_0_THERMALINTERFACESERVICE_H

#include "thermal_interface_stub.h"

namespace hdi {
namespace thermal {
namespace v1_0 {
class ThermalInterfaceService : public ThermalInterfaceStub {
public:
    ThermalInterfaceService();
    virtual ~ThermalInterfaceService() {}

    int32_t SetCpuFreq(int32_t freq) override;

    int32_t SetGpuFreq(int32_t freq) override;

    int32_t SetBatteryCurrent(int32_t current) override;

    int32_t GetThermalZoneInfo(HdfThermalCallbackInfo& event) override;

    int32_t Register(const sptr<IThermalCallback>& callbackObj) override;

    int32_t Unregister() override;
    int32_t Init();
};
} // v1_0
} // thermal
} // hdi

#endif // HDI_THERMAL_V1_0_THERMALINTERFACESERVICE_H