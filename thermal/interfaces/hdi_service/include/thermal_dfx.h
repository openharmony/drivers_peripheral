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

#ifndef THERMAL_DFX_H
#define THERMAL_DFX_H

#include <map>
#include <memory>
#include <fstream>
#include <string>
#include "thermal_hdf_config.h"

namespace OHOS {
namespace HDI {
namespace Thermal {
namespace V1_0 {
class ThermalDfx {
public:
    ThermalDfx() {}
    ~ThermalDfx() {}

    int32_t Init();
private:
    void UpdateInterval();
    void GetTraceInfo();
    void StartThread();
    void CreateLogFile();
    void ProcessLogInfo(std::string& logFile, bool isEmpty);
    void WriteToFile(std::ofstream& wStream, std::string& currentTime, uint32_t paramWidth);
    void CompressFile();
    bool PrepareWriteDfxLog();
    int32_t ParseValue(const std::string& path, std::string& value);
    int32_t LoopingThreadEntry();
    std::string GetFileNameIndex(const uint32_t index);
};
} // V1_0
} // Thermal
} // HDI
} // OHOS
#endif // THERMAL_DFX_H
