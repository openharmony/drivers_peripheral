/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#ifndef OHOS_HDI_VIBRATOR_V1_1_VIBRATORINTERFACEIMPL_H
#define OHOS_HDI_VIBRATOR_V1_1_VIBRATORINTERFACEIMPL_H

#include "ivibrator_interface_vdi.h"
#include "ivibrator_type_vdi.h"

namespace OHOS {
namespace HDI {
namespace Vibrator {
namespace V1_1 {
class VibratorInterfaceImpl : public IVibratorInterfaceVdi {
public:
    VibratorInterfaceImpl() {}
    ~VibratorInterfaceImpl() {}
    int32_t Init(void) override;
    int32_t StartOnce(uint32_t duration) override;
    int32_t Start(const std::string &effectType) override;
    int32_t Stop(HdfVibratorModeVdi mode) override;
    int32_t GetVibratorInfo(std::vector<HdfVibratorInfoVdi> &vibratorInfo) override;
    int32_t EnableVibratorModulation(uint32_t duration, uint16_t intensity, int16_t frequency) override;
    int32_t EnableCompositeEffect(const HdfCompositeEffectVdi& effect) override;
    int32_t GetEffectInfo(const std::string &effectType, HdfEffectInfoVdi &effectInfo) override;
    int32_t IsVibratorRunning(bool& state) override;
    int32_t PlayHapticPattern(const HapticPaketVdi& pkgVdi) override;
    int32_t GetHapticCapacity(HapticCapacityVdi& hapticCapacityVdi) override;
    int32_t GetHapticStartUpTime(int32_t mode, int32_t& startUpTime) override;
    int32_t StartByIntensity(const std::string& effectType, uint16_t intensity) override;
};
} // V1_1
} // Vibrator
} // HDI
} // OHOS

#endif // OHOS_HDI_VIBRATOR_V1_1_VIBRATORINTERFACEIMPL_H