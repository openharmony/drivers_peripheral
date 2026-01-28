/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#ifndef SIGNALAI_RECORDER_H
#define SIGNALAI_RECORDER_H

#include <filesystem>
#include <string>
#include "sensor_sdc_model.h"

namespace OHOS {
namespace AppExecFwk {
    class EventHandler;
}
namespace Telephony {

struct SdcDataHeader {
    unsigned int fifoCount;
    unsigned int fifoWriteIndex;
    unsigned long long reserved[2];
};

struct SdcDataVec3 {
    float x;
    float y;
    float z;
    unsigned int accuracy;
    long long timestamp;
    unsigned long long sysCnt;
};

struct SdcBufferInfo {
    int addrOffset;
    unsigned int fifoCount;
    std::atomic_uint32_t curWriteIdx;  // 本次写指针位置
    std::atomic_uint32_t lastWriteIdx;  // 上次写指针位置
};

constexpr int SDC_HEADER_SIZE = sizeof(SdcDataHeader);
constexpr int SDC_VEC3_SIZE = sizeof(SdcDataVec3);

class SignalAIRecorder {
public:
    SignalAIRecorder();
    ~SignalAIRecorder();
    void Init();
    void SetCurWriteIdx(unsigned int accIdx, unsigned int gyrIdx, bool isForce);
    void SetSdcSensorInfo(uint8_t *sensorShareAddr, int accAddrOffset, int gyrAddrOffset);
    void PreSetInfo(unsigned int accFifoCount, unsigned int gyrFifoCount, unsigned int accIdx, unsigned int gyrIdx);
private:
    void WriteToFile();
    void CleanOldLogs();
    const SdcDataVec3 *ReadSingleDataByIdx(int offset, long curReadIndex);
    void HandleLogFile(std::string& fileName, SdcBufferInfo &bufInfo);
    void CleanOldFiles(std::vector<std::filesystem::path>& files);
    void SortByLastWriteTime(std::vector<std::filesystem::path>& files);

    std::atomic_uint32_t count_ = 0;
    unsigned int halfMinFifoCount_ = 1;
    SdcBufferInfo accBufInfo_ = {-1, 1, 0, 0};
    SdcBufferInfo gyrBufInfo_ = {-1, 1, 0, 0};
    bool isBeta_ = false;
    std::shared_ptr<AppExecFwk::EventHandler> handler_ = nullptr;
    uint8_t* sensorShareAddr_ = nullptr;
};
}  // namespace Telephony
}  // namespace OHOS
#endif  // SIGNALAI_RECORDER_H
