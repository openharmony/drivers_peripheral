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

#ifndef OHOS_HDI_VIBRATOR_V1_1_VIBRATORINTERFACEIMPL_VDI_H
#define OHOS_HDI_VIBRATOR_V1_1_VIBRATORINTERFACEIMPL_VDI_H

#include <stdint.h>
#include <vector>
#include <hdf_base.h>
#include "hdf_load_vdi.h"
#include "ivibrator_type_vdi.h"
#include "v1_3/ivibrator_interface.h"

namespace OHOS {
namespace HDI {
namespace Vibrator {
namespace V1_1 {

#define HDI_VIBRATOR_VDI_LIBNAME "libhdi_vibrator_impl.z.so"

class IVibratorInterfaceVdi {
public:
    virtual ~IVibratorInterfaceVdi() = default;
    virtual int32_t Init() = 0;
    virtual int32_t StartOnce(uint32_t duration) = 0;
    virtual int32_t Start(const std::string &effectType) = 0;
    virtual int32_t Stop(HdfVibratorModeVdi mode) = 0;
    virtual int32_t GetVibratorInfo(std::vector<HdfVibratorInfoVdi> &vibratorInfo) = 0;
    virtual int32_t EnableVibratorModulation(uint32_t duration, uint16_t intensity, int16_t frequency) = 0;
    virtual int32_t EnableCompositeEffect(const HdfCompositeEffectVdi& effect) = 0;
    virtual int32_t GetEffectInfo(const std::string &effectType, HdfEffectInfoVdi &effectInfo) = 0;
    virtual int32_t IsVibratorRunning(bool& state) = 0;
    virtual int32_t PlayHapticPattern(const HapticPaketVdi& pkg) = 0;
    virtual int32_t GetHapticCapacity(HapticCapacityVdi& hapticCapacity) = 0;
    virtual int32_t GetHapticStartUpTime(int32_t mode, int32_t& startUpTime) = 0;
    virtual int32_t StartByIntensity(const std::string& effectType, uint16_t intensity) {return HDF_SUCCESS;};
    virtual int32_t GetAllWaveInfo(int32_t vibratorId, std::vector<HdfWaveInformation> &info) {return HDF_SUCCESS;};
};
struct VdiWrapperVibrator {
    struct HdfVdiBase base;
    IVibratorInterfaceVdi *vibratorModule;
};
} // V1_1
} // Vibrator
} // HDI
} // OHOS

#endif // OHOS_HDI_VIBRATOR_V1_1_VIBRATORINTERFACEIMPL_VDI_H