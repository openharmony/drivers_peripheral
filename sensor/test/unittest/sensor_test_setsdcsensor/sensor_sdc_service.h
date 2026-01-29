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

#ifndef SIGNALAI_SERVICE_H
#define SIGNALAI_SERVICE_H

#include <deque>
#include "hold_posture_info.h"
#include "sensor_sdc_manager.h"
#include "sensor_sdc_recorder.h"

namespace OHOS {
namespace Telephony {

constexpr int MAX_LOG_PRINT_NUM = 10;

struct BufferInfo {
    int addrOffset;
    unsigned int fifoCount;
    bool firstRunFlg;
    long curWriteIdx;
    long lastWriteIdx;
};

struct LogPrintInfo {
    long long accTimestamp;
    long long gyrTimestamp;
    int singleResult;
    int finalResult;
    int orient;
};

struct LogPrintVec {
    LogPrintInfo printInfo[MAX_LOG_PRINT_NUM];
    int idx;
};

class SignalAIService {
public:
    bool InitNetwork(const std::string& filePath, const std::vector<std::string>& validFiles);
    void ReleaseAi();
    void OnReceivedSensorEvent();
    HoldPostureErrorCode DecodeMemory(int &result);
    void SetAccuracyThreshold(float threshold);
    void SetAccumulateNum(int num);
    HoldPostureErrorCode DecodeSdcHeader(unsigned int &accFifoWriteIdx, unsigned int &gyrFifoWriteIdx);
    void SetSdcSensorInfo(uint8_t* sensorShareAddr, int accAddrOffset, int gyrAddrOffset);
    void SetLastFifoWriteIdx(unsigned int accLastWriteIdx, unsigned int gyrLastWriteIdx, unsigned int accFifoCount,
        unsigned int gyrFifoCount, time_t fifoWriteIdxSetTime);
    void SetFrameSlideTimeMs(int time);
    void SetOrient(uint32_t orient);

private:
    void LinearInterpolationSinglePoint(int interpIdx, long long timestamp, int leftIdx,
        ImuSensorData (&sensorBuffer)[SENSOR_BUFF_LEN], ImuSensorData (&interpolationBuffer)[SAMPLE_NUM]);
    int FindSegment(int curIdx, int sampleNum, long long baselineTimestamp,
        ImuSensorData (&sensorBuffer)[SENSOR_BUFF_LEN], int num);
    HoldPostureErrorCode LinearInterpolation(long long baselineTimestamp, int accStartIdx, int accEndIdx,
                                int gyrStartIdx, int gyrEndIdx);
    int BufferIndexWrap(long curIdx, long bufferSize);
    int FindBufferStartIdx(int lastStartIdx, int lastEndIdx, long long timestamp,
        ImuSensorData (&sensorBuffer)[SENSOR_BUFF_LEN]);
    int GetOrientation();
    long GetReadDataNum(long curWriteIdx, long lastWriteIdx, unsigned int bufferCount);
    SdcDataVec3* ReadSingleDataByIdx(int offset, long curReadIndex);
    HoldPostureErrorCode Preprocess(int accFrameEndIdx, int gyrFrameEndIdx);
    HoldPostureErrorCode Postprocess(int &result, int &finalResult);
    HoldPostureErrorCode HandleAccGyrData(int &frameStartIdx, BufferInfo &bufInfo, SensorBuffer &frame);
    int JudgeSampleInterval(int curIdx, ImuSensorData (&sensorData)[SENSOR_BUFF_LEN]);
    void Softmax(const float (&inputs)[MS_AI_OUTPUT_SIZE], float (&output)[MS_AI_OUTPUT_SIZE]);
    int GetSingleHoldResult(const float (&inputs)[MS_AI_OUTPUT_SIZE]);
    int GetAccumulatedHoldResult(const int curHoldPostureIdx);
    int GetBufferIdxIntervalNum(int startIdx, int endIdx, int bufferLen);
    DetrendSensorData GetMean(DetrendSensorData (&sensorData)[SAMPLE_NUM]);
    DetrendSensorData GetStd(DetrendSensorData (&sensorData)[SAMPLE_NUM], DetrendSensorData &mean);
    void ZScoreNorm(DetrendSensorData (&detrendSensorData)[SAMPLE_NUM], ImuSensorData (&sensorData)[SAMPLE_NUM],
        DetrendSensorData &mean, DetrendSensorData &std);
    void MovingAverage(DetrendSensorData (&data)[SAMPLE_NUM], ImuSensorData (&arr)[SAMPLE_NUM]);
    void SetSensorBuffer(ImuSensorData (&sensorData)[SENSOR_BUFF_LEN], long curBufferIdx, SdcDataVec3 *dataVec);
    HoldPostureErrorCode JudgeInfer(int &finalResult);
    int GetSdcCacheSlideNum(long long &startTimestamp, long long &endTimestamp, BufferInfo &bufInfo);
    void GetFrameSlideIdx(long long startTimestamp, long long endTimestamp, std::vector<long> &idxList,
        BufferInfo &bufInfo, int frameSlideNum);
    HoldPostureErrorCode HandleFirstRunWithCache(int &finalResult);
    int GetMode();
    HoldPostureErrorCode HandleMultiShotWithCache(long long accEndTimestamp, long long gyrEndTimestamp,
        int frameSlideNum, int &finalResult);
    void UpdatePrintInfo(long long accTime, long long gyrTime, int result, int finalResult);

    unsigned int accWriteIdxUnwrap_ = 0;
    unsigned int gyrWriteIdxUnwrap_ = 0;
    int lastHoldResult_ = MS_AI_OUTPUT_SIZE;
    LogPrintVec logVec_;
    uint32_t orient_ = 0;
    uint8_t* sensorShareAddr_ = nullptr;
    time_t lastFifoWriteIdxSetTime_ = 0;
    float accuracyThreshold_ = 0.0;
    int accumulatedNum_ = 5;
    SensorBuffer acceFrame_;
    SensorBuffer gyroFrame_;
    SensorInterpBuffer acceInterpolationFrame_;
    SensorInterpBuffer gyroInterpolationFrame_;
    DetrendSensorData accDetrendData_[SAMPLE_NUM];
    DetrendSensorData gyrDetrendData_[SAMPLE_NUM];
    BufferInfo accBufInfo_ = {-1, 0, true, 0, -1};
    BufferInfo gyrBufInfo_ = {-1, 0, true, 0, -1};
    unsigned int lastAccWriteIdxUnWrap_ = 0;
    unsigned int lastGyrWriteIdxUnWrap_ = 0;
    int accFrameStartIdx_ = 0;
    int gyrFrameStartIdx_ = 0;
    long long frameStartTimestampNs_ = 0;
    long long frameEndTimestampNs_ = 0;
    int lastHoldPostureIdx_ = -1;
    std::deque<int> holdResultQue_;
    bool warmUpEnd_ = false;
    int frameSlideTimeMs_ = 100;
    SignalAIManager signalAIManager_;
    SignalAIRecorder recorder_;
};
}  // Telephony
}  // OHOS
#endif  // SIGNALAI_SERVICE_H