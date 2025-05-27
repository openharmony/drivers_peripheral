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

#ifndef OHOS_HDI_VIBRATOR_V2_0_VIBRAORINTERFACESERVICE_H
#define OHOS_HDI_VIBRATOR_V2_0_VIBRAORINTERFACESERVICE_H

#include "v2_0/ivibrator_interface.h"
#include "v1_1/ivibrator_interface_vdi.h"

namespace OHOS {
namespace HDI {
namespace Vibrator {
namespace V2_0 {
using namespace OHOS::HDI::Vibrator;
using namespace OHOS::HDI::Vibrator::V1_1;

class VibratorIfService : public V2_0::IVibratorInterface  {
public:
    //version 2.0
    VibratorIfService();
    ~VibratorIfService();
    int32_t Init(void);
    int32_t StartOnce(const OHOS::HDI::Vibrator::V2_0::DeviceVibratorInfo& deviceVibratorInfo,
                      uint32_t duration) override;
    int32_t Start(const OHOS::HDI::Vibrator::V2_0::DeviceVibratorInfo& deviceVibratorInfo,
                  const std::string &effectType) override;
    int32_t Stop(const OHOS::HDI::Vibrator::V2_0::DeviceVibratorInfo& deviceVibratorInfo,
                 V2_0::HdfVibratorMode mode) override;
    int32_t GetVibratorInfo(std::vector<V2_0::HdfVibratorInfo> &vibratorInfo) override;
    int32_t GetDeviceVibratorInfo(const OHOS::HDI::Vibrator::V2_0::DeviceVibratorInfo& deviceVibratorInfo,
                                  std::vector<HdfVibratorInfo> &vibratorInfo) override;
    int32_t GetVibratorIdSingle(const OHOS::HDI::Vibrator::V2_0::DeviceVibratorInfo& deviceVibratorInfo,
                                std::vector<HdfVibratorInfo> &vibratorInfo) override;
    int32_t EnableVibratorModulation(const OHOS::HDI::Vibrator::V2_0::DeviceVibratorInfo& deviceVibratorInfo,
                                     uint32_t duration, uint16_t intensity, int16_t frequency) override;
    int32_t EnableCompositeEffect(const OHOS::HDI::Vibrator::V2_0::DeviceVibratorInfo& deviceVibratorInfo,
                                  const HdfCompositeEffect& effect) override;
    int32_t GetEffectInfo(const OHOS::HDI::Vibrator::V2_0::DeviceVibratorInfo& deviceVibratorInfo,
                          const std::string &effectType, V2_0::HdfEffectInfo &effectInfo) override;
    int32_t IsVibratorRunning(const OHOS::HDI::Vibrator::V2_0::DeviceVibratorInfo& deviceVibratorInfo,
                              bool& state) override;
    int32_t PlayHapticPattern(const OHOS::HDI::Vibrator::V2_0::DeviceVibratorInfo& deviceVibratorInfo,
                              const HapticPaket& pkg) override;
    int32_t GetHapticCapacity(const OHOS::HDI::Vibrator::V2_0::DeviceVibratorInfo& deviceVibratorInfo,
                              V2_0::HapticCapacity& hapticCapacity) override;
    int32_t GetHapticStartUpTime(const OHOS::HDI::Vibrator::V2_0::DeviceVibratorInfo& deviceVibratorInfo,
                                 int32_t mode, int32_t& startUpTime) override;
    int32_t StartByIntensity(const OHOS::HDI::Vibrator::V2_0::DeviceVibratorInfo& deviceVibratorInfo,
                             const std::string& effectType, uint16_t intensity) override;
    int32_t GetAllWaveInfo(const OHOS::HDI::Vibrator::V2_0::DeviceVibratorInfo& deviceVibratorInfo,
                           std::vector<HdfWaveInformation> &info) override;
    int32_t RegVibratorPlugCallback(const sptr<IVibratorPlugCallback> &callbackObj) override;
    int32_t UnRegVibratorPlugCallback(const sptr<IVibratorPlugCallback> &callbackObj) override;
    int32_t GetVibratorVdiImpl();

private:
    OHOS::HDI::Vibrator::V1_1::IVibratorInterfaceVdi *vibratorVdiImplV1_1_ = nullptr;
    struct HdfVdiObject *vdi_ = nullptr;
};
} // V2_0
} // Vibrator
} // HDI
} // OHOS

#endif // OHOS_HDI_VIBRATOR_V2_0_VIBRAORINTERFACESERVICE_H