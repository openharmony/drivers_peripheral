/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef OHOS_HDI_VIBRATOR_V1_3_VIBRAORINTERFACESERVICE_H
#define OHOS_HDI_VIBRATOR_V1_3_VIBRAORINTERFACESERVICE_H

#include "v1_3/ivibrator_interface.h"
#include "ivibrator_interface_vdi.h"
#include "ivibrator_type_vdi.h"

namespace OHOS {
namespace HDI {
namespace Vibrator {
namespace V1_3 {
class VibratorIfService : public IVibratorInterface {
public:
    VibratorIfService();
    ~VibratorIfService();
    int32_t Init(void);
    int32_t StartOnce(uint32_t duration) override;
    int32_t Start(const std::string &effectType) override;
    int32_t Stop(HdfVibratorMode mode) override;
    int32_t StopV1_2(int32_t mode) override;
    int32_t GetVibratorInfo(std::vector<HdfVibratorInfo> &vibratorInfo) override;
    int32_t EnableVibratorModulation(uint32_t duration, uint16_t intensity, int16_t frequency) override;
    int32_t EnableCompositeEffect(const HdfCompositeEffect& effect) override;
    int32_t GetEffectInfo(const std::string &effectType, HdfEffectInfo &effectInfo) override;
    int32_t IsVibratorRunning(bool& state) override;
    int32_t PlayHapticPattern(const HapticPaket& pkg) override;
    int32_t GetHapticCapacity(HapticCapacity& hapticCapacity) override;
    int32_t GetHapticStartUpTime(int32_t mode, int32_t& startUpTime) override;
    int32_t StartByIntensity(const std::string& effectType, uint16_t intensity) override;
    int32_t GetAllWaveInfo(int32_t vibratorId, std::vector<HdfWaveInformation> &info) override;
    int32_t GetVibratorVdiImpl();

private:
    IVibratorInterfaceVdi *vibratorVdiImpl_ = nullptr;
    struct HdfVdiObject *vdi_ = nullptr;
};
} // V1_3
} // Vibrator
} // HDI
} // OHOS

#endif // OHOS_HDI_VIBRATOR_V1_3_VIBRAORINTERFACESERVICE_H