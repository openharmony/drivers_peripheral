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

#include "v1_1/ivibrator_interface.h"

namespace OHOS {
namespace HDI {
namespace Vibrator {
namespace V1_1 {
class VibratorInterfaceImpl : public IVibratorInterface {
public:
    virtual ~VibratorInterfaceImpl() {}
    int32_t StartOnce(uint32_t duration) override;
    int32_t Start(const std::string &effectType) override;
    int32_t Stop(HdfVibratorMode mode) override;
    int32_t GetVibratorInfo(std::vector<HdfVibratorInfo> &vibratorInfo) override;
    int32_t EnableVibratorModulation(uint32_t duration, uint16_t intensity, int16_t frequency) override;
    int32_t EnableCompositeEffect(const HdfCompositeEffect& effect) override;
    int32_t GetEffectInfo(const std::string &effectType, HdfEffectInfo &effectInfo) override;
    int32_t IsVibratorRunning(bool& state) override;;
};
} // V1_1
} // Vibrator
} // HDI
} // OHOS

#endif // OHOS_HDI_VIBRATOR_V1_1_VIBRATORINTERFACEIMPL_H