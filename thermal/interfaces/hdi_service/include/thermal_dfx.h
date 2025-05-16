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

#ifndef THERMAL_DFX_H
#define THERMAL_DFX_H

#include <atomic>
#include <fstream>
#include <map>
#include <memory>
#include <string>
#include <thread>

#include "nocopyable.h"
#include "thermal_hdf_config.h"

namespace OHOS {
namespace HDI {
namespace Thermal {
namespace V1_1 {
class ThermalDfx : public NoCopyable {
public:
    ThermalDfx();
    ~ThermalDfx();

    void Init();
    void DoWork();
    uint32_t GetInterval();
    static ThermalDfx& GetInstance();
    static void DestroyInstance();

private:
    std::string CanonicalizeSpecPath(const char* src);
    bool Compress(const std::string& dataFile, const std::string& destFile);
    void CreateLogFile();
    void ProcessLogInfo(std::string& logFile, bool isEmpty);
    void WriteToEmptyFile(std::ofstream& wStream, std::string& currentTime);
    void WriteToFile(std::ofstream& wStream, std::string& currentTime);
    void CompressFile();
    void ReportDataHisysevent();
    void WriteDataHisysevent();
    double GetDeviceValidSize(const std::string& path);
    uint64_t GetDirectorySize(const std::string& directoryPath);
    bool PrepareWriteDfxLog();
    std::string GetFileNameIndex(const uint32_t index);
    int32_t GetIntParameter(const std::string& key, const int32_t def, const int32_t minValue);
    bool GetBoolParameter(const std::string& key, const bool def);
    void WidthWatchCallback(const std::string& value);
    void IntervalWatchCallback(const std::string& value);
    void EnableWatchCallback(const std::string& value);
    static void InfoChangedCallback(const char* key, const char* value, void* context);

    int64_t beginTimeMs_;
    std::atomic_uint8_t width_;
    std::atomic_uint32_t interval_;
    std::atomic_bool enable_;
    static std::mutex mutexInstance_;
    static std::shared_ptr<ThermalDfx> instance_;
};
} // V1_1
} // Thermal
} // HDI
} // OHOS
#endif // THERMAL_DFX_H
