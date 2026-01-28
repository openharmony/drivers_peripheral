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

#include "sensor_sdc_service.h"
#include <map>
#include "parameters.h"
#include "securec.h"

namespace OHOS {
namespace Telephony {

enum class Orient : uint32_t {
    PORTRAIT = 0,
    LANDSCAPE,
    PORTRAIT_INV,
    LANDSCAPE_INV,
    UNKNOWN
};

static constexpr long long FRAME_DURATION_TIME_MS = 500;  // 模型输入时间窗
static constexpr long long FRAME_EXTRA_MS = 10;  // 额外等待10ms 确保不会插值时不会外插
static constexpr long long TIME_UNIT_S_TO_MS = 1000;                                       // s到ms的单位换算
static constexpr long long TIME_UNIT_MS_TO_NS = 1000000;                                   // ms到ns的单位换算
static constexpr int SENSOR_SAMPLE_RATE_HZ = 100;                                          // sensor的采样率
static constexpr int SENSOR_SAMPLE_PERIOD_MS = TIME_UNIT_S_TO_MS / SENSOR_SAMPLE_RATE_HZ;  // sensor采样间隔
static constexpr long SENSOR_SAMPLE_PERIOD_TOLERANCE_NS = (SENSOR_SAMPLE_PERIOD_MS + 4) * TIME_UNIT_MS_TO_NS;
static constexpr int ORIENT_PORTRAIT = 0;
static constexpr int ORIENT_LANDSCAPE_INV = 1;
static constexpr int ORIENT_LANDSCAPE = 2;
static constexpr int ORIENT_PORTRAIT_INV = 3;
static constexpr int MIN_ACCUMULATE_NUM = 2;
static constexpr int WARM_UP_TIME_INTERVAL = 1;  // 1s后的数据均达到了投票缓存所需的数据个数
static constexpr int MIN_FRAME_DATA_NUM =
    FRAME_DURATION_TIME_MS * SENSOR_SAMPLE_RATE_HZ / TIME_UNIT_S_TO_MS - 5;  // 能容忍的最少数据个数

void SignalAIService::SetSdcSensorInfo(uint8_t *sensorShareAddr, int accAddrOffset, int gyrAddrOffset)
{
    sensorShareAddr_ = sensorShareAddr;
    accBufInfo_.addrOffset = accAddrOffset;
    gyrBufInfo_.addrOffset = gyrAddrOffset;
    recorder_.SetSdcSensorInfo(sensorShareAddr, accAddrOffset, gyrAddrOffset);
}

void SignalAIService::SetOrient(uint32_t orient)
{
    switch (orient) {
        case static_cast<uint32_t>(Orient::LANDSCAPE):  // 1 直板机横屏摄像头朝右
            orient_ = ORIENT_LANDSCAPE;
            break;
        case static_cast<uint32_t>(Orient::PORTRAIT_INV):  // 2 反向竖屏
            orient_ = ORIENT_PORTRAIT_INV;
            break;
        case static_cast<uint32_t>(Orient::LANDSCAPE_INV):  // 3 直板机横屏摄像头朝左
            orient_ = ORIENT_LANDSCAPE_INV;
            break;
        default:  // 0 或者默认竖屏
            orient_ = ORIENT_PORTRAIT;
    }
}

void SignalAIService::SetFrameSlideTimeMs(int time)
{
    printf("SIGNALAI:Service:FrameSlideTime = %d", time);
    frameSlideTimeMs_ = time;
}

void SignalAIService::SetAccumulateNum(int num)
{
    printf("SIGNALAI:Service:AccumulateNum = %d", num);
    accumulatedNum_ = num;
    logVec_.idx = 0;
}

void SignalAIService::SetAccuracyThreshold(float threshold)
{
    printf("SIGNALAI:Service:AccuracyThreshold = %.3f", threshold);
    accuracyThreshold_ = threshold;
}

// 计算softmax函数
void SignalAIService::Softmax(const float (&inputs)[MS_AI_OUTPUT_SIZE], float (&output)[MS_AI_OUTPUT_SIZE])
{
    float max = *std::max_element(inputs, inputs + MS_AI_OUTPUT_SIZE);

    float sum = 1e-10;
    for (int i = 0; i < MS_AI_OUTPUT_SIZE; i++) {
        output[i] = std::exp(inputs[i] - max);
        sum += output[i];
    }

    for (int i = 0; i < MS_AI_OUTPUT_SIZE; i++) {
        output[i] = output[i] / sum;
    }
}

// 模型单次输出映射到握姿
int SignalAIService::GetSingleHoldResult(const float (&inputs)[MS_AI_OUTPUT_SIZE])
{
    int maxIdx = 0;
    float maxVal = inputs[maxIdx];
    for (int i = 1; i < MS_AI_OUTPUT_SIZE; i++) {
        if (inputs[i] > maxVal) {
            maxVal = inputs[i];
            maxIdx = i;
        }
    }
    printf("SIGNALAI:Service:SingleHoldResult maxVal=%f", maxVal);
    if (maxVal < accuracyThreshold_) {
        maxIdx = -1;
    }
    return maxIdx;
}

// 获取众数
int SignalAIService::GetMode()
{
    std::map<int, int> countMap;
    // 遍历队列，统计每个元素的出现次数
    for (auto it = holdResultQue_.begin(); it < holdResultQue_.end(); it++) {
        countMap[*it]++;
    }

    // 找到出现次数最多的元素
    int maxCount = 0;
    int mode = 0;
    for (const auto &pair : countMap) {
        if (pair.second >= maxCount) {
            maxCount = pair.second;
            mode = pair.first;
        }
    }
    return mode;
}

// 多次握姿累计
int SignalAIService::GetAccumulatedHoldResult(const int curHoldPostureIdx)
{
    if (accumulatedNum_ < MIN_ACCUMULATE_NUM) {
        printf("SIGNALAI:Service:AccumulatedHoldResult direct return %d", curHoldPostureIdx);
        return curHoldPostureIdx;
    }
    if (holdResultQue_.size() >= static_cast<size_t>(accumulatedNum_)) {
        holdResultQue_.pop_front();
    }
    holdResultQue_.push_back(curHoldPostureIdx);

    if (holdResultQue_.size() < static_cast<size_t>(accumulatedNum_)) {
        printf("SIGNALAI:Service:AccumulatedHoldResult return mode");
        lastHoldPostureIdx_ = GetMode();
        return lastHoldPostureIdx_;
    }

    for (auto it = holdResultQue_.begin(); it < holdResultQue_.end(); it++) {
        if ((*it) != curHoldPostureIdx) {
            printf(
                "SIGNALAI:Service:AccumulatedHoldResult return lastIdx = %d",
                lastHoldPostureIdx_);
            return lastHoldPostureIdx_;  // 输出上一次的结果
        }
    }

    lastHoldPostureIdx_ = curHoldPostureIdx;
    printf(
        "SIGNALAI:Service:AccumulatedHoldResult return curIdx = %d",
        curHoldPostureIdx);
    return curHoldPostureIdx;  // 输出当前姿态
}

bool SignalAIService::InitNetwork(const std::string& filePath, const std::vector<std::string>& validFiles)
{
    memset_s(&acceFrame_, sizeof(SensorBuffer), 0, sizeof(SensorBuffer));
    memset_s(&gyroFrame_, sizeof(SensorBuffer), 0, sizeof(SensorBuffer));
    if (signalAIManager_.InitModel(filePath.c_str(), validFiles)) {
        printf("SIGNALAI:Service:InitNetwork success.");
        recorder_.Init();
        return true;
    } else {
        printf("SIGNALAI:Service:InitNetwork fail.");
        return false;
    }
}

int SignalAIService::FindBufferStartIdx(int lastStartIdx, int lastEndIdx, long long timestamp,
    ImuSensorData (&sensorBuffer)[SENSOR_BUFF_LEN])
{
    int sampleNum = GetBufferIdxIntervalNum(lastStartIdx, lastEndIdx, SENSOR_BUFF_LEN);
    for (int i = 0; i < sampleNum - 1; ++i) {
        int nextIdx = BufferIndexWrap(lastStartIdx + i + 1, SENSOR_BUFF_LEN);
        if (sensorBuffer[nextIdx].timestamp >= timestamp) {
            return BufferIndexWrap(lastStartIdx + i, SENSOR_BUFF_LEN);
        }
    }
    return BufferIndexWrap(lastEndIdx - 1, SENSOR_BUFF_LEN);
}

int SignalAIService::BufferIndexWrap(long curIdx, long bufferSize)
{
    if (bufferSize == 0) {
        return -1;
    }
    curIdx = curIdx % bufferSize;
    // 如果 curIdx 为负数，加上 bufferSize 使其变为正数
    if (curIdx < 0) {
        curIdx += bufferSize;
    }
    return curIdx;
}

void SignalAIService::LinearInterpolationSinglePoint(int interpIdx, long long timestamp, int leftIdx,
    ImuSensorData (&sensorBuffer)[SENSOR_BUFF_LEN], ImuSensorData (&interpolationBuffer)[SAMPLE_NUM])
{
    leftIdx = BufferIndexWrap(leftIdx, SENSOR_BUFF_LEN);
    int rightIdx = BufferIndexWrap(leftIdx + 1, SENSOR_BUFF_LEN);
    long long leftTimestamp = sensorBuffer[leftIdx].timestamp;
    long long rightTimestamp = sensorBuffer[rightIdx].timestamp;

    // 检查分母是否为零
    if (rightTimestamp == leftTimestamp) {
        // 如果时间戳相同，直接使用 leftIdx 对应的数据点
        interpolationBuffer[interpIdx] = sensorBuffer[leftIdx];
    } else {
        double fraction = static_cast<double>(timestamp - leftTimestamp) / (rightTimestamp - leftTimestamp);
        interpolationBuffer[interpIdx].timestamp = timestamp;
        interpolationBuffer[interpIdx].x =
            sensorBuffer[leftIdx].x + (sensorBuffer[rightIdx].x - sensorBuffer[leftIdx].x) * fraction;
        interpolationBuffer[interpIdx].y =
            sensorBuffer[leftIdx].y + (sensorBuffer[rightIdx].y - sensorBuffer[leftIdx].y) * fraction;
        interpolationBuffer[interpIdx].z =
            sensorBuffer[leftIdx].z + (sensorBuffer[rightIdx].z - sensorBuffer[leftIdx].z) * fraction;
    }
}

int SignalAIService::FindSegment(int startIdx, int offset, long long baselineTimestamp,
    ImuSensorData (&sensorBuffer)[SENSOR_BUFF_LEN], int sampleNum)
{
    int i = offset;
    int nextIdx = 0;
    int curIdx;
    for (; i < sampleNum - 1; ++i) {
        curIdx = startIdx + i;
        nextIdx = BufferIndexWrap(curIdx + 1, SENSOR_BUFF_LEN);
        if (baselineTimestamp < sensorBuffer[nextIdx].timestamp) {
            return i;
        }
    }
    return i - 1;
}

int SignalAIService::GetBufferIdxIntervalNum(int startIdx, int endIdx, int bufferLen)
{
    int num = 0;
    if (startIdx > endIdx) {
        num = bufferLen - startIdx + endIdx + 1;
    } else {
        num = endIdx - startIdx + 1;
    }
    return num;
}

HoldPostureErrorCode SignalAIService::LinearInterpolation(
    long long baselineTimestamp, int accStartIdx, int accEndIdx, int gyrStartIdx, int gyrEndIdx)
{
    int accSampleNum = GetBufferIdxIntervalNum(accStartIdx, accEndIdx, SENSOR_BUFF_LEN);
    int gyrSampleNum = GetBufferIdxIntervalNum(gyrStartIdx, gyrEndIdx, SENSOR_BUFF_LEN);
    if (accSampleNum < MIN_FRAME_DATA_NUM || gyrSampleNum < MIN_FRAME_DATA_NUM) {  // 说明丢数过多
        printf("SIGNALAI:Service:Process less sample num %d, %d, %d",
            accSampleNum, gyrSampleNum, MIN_FRAME_DATA_NUM);
        return HoldPostureErrorCode::SENSOR_DATA_ERROR;
    }

    int accOffset = 0;
    int gyrOffset = 0;
    for (int i = 0; i < SAMPLE_NUM; i++) {
        accOffset = FindSegment(accStartIdx, accOffset, baselineTimestamp, acceFrame_.sensorBuffer, accSampleNum);

        LinearInterpolationSinglePoint(i, baselineTimestamp, accStartIdx + accOffset, acceFrame_.sensorBuffer,
            acceInterpolationFrame_.sensorBuffer);

        gyrOffset = FindSegment(gyrStartIdx, gyrOffset, baselineTimestamp, gyroFrame_.sensorBuffer, gyrSampleNum);

        LinearInterpolationSinglePoint(i, baselineTimestamp, gyrStartIdx + gyrOffset, gyroFrame_.sensorBuffer,
            gyroInterpolationFrame_.sensorBuffer);
        baselineTimestamp = baselineTimestamp + SENSOR_SAMPLE_PERIOD_MS * TIME_UNIT_MS_TO_NS;
    }
    return HoldPostureErrorCode::SUCCESS;
}

long SignalAIService::GetReadDataNum(long curWriteIdx, long lastWriteIdx, unsigned int bufferCount)
{
    long dataNum;
    if (lastWriteIdx < curWriteIdx) {
        dataNum = curWriteIdx - lastWriteIdx;
    } else {  // 循环buffer环回
        dataNum = static_cast<long long>(bufferCount) - lastWriteIdx + curWriteIdx;
    }
    return dataNum;
}

// 从sensor sdc共享内存中获取数据
SdcDataVec3 *SignalAIService::ReadSingleDataByIdx(int offset, long curReadIndex)
{
    return reinterpret_cast<SdcDataVec3 *>(&sensorShareAddr_[offset + SDC_HEADER_SIZE + SDC_VEC3_SIZE * curReadIndex]);
}

int SignalAIService::JudgeSampleInterval(int curIdx, ImuSensorData (&sensorData)[SENSOR_BUFF_LEN])
{
    if (curIdx == 0) {
        return 0;
    }
    long long timestampDiff = sensorData[curIdx].timestamp - sensorData[curIdx - 1].timestamp;
    if (timestampDiff >= SENSOR_SAMPLE_PERIOD_TOLERANCE_NS || timestampDiff <= 0) {
        printf(
            "SIGNALAI: unexpected sensor sample time interval, diff = %lld, timeL = "
            "%lld, timeR = %lld, curIdx = %d",
            timestampDiff, sensorData[curIdx - 1].timestamp, sensorData[curIdx].timestamp, curIdx);
        return 1;
    }
    return 0;
}

void SignalAIService::SetSensorBuffer(ImuSensorData (&sensorData)[SENSOR_BUFF_LEN], long curBufferIdx,
    SdcDataVec3 *dataVec)
{
    if (curBufferIdx < SENSOR_BUFF_LEN) {
        sensorData[curBufferIdx].x = dataVec->x;
        sensorData[curBufferIdx].y = dataVec->y;
        sensorData[curBufferIdx].z = dataVec->z;
        sensorData[curBufferIdx].timestamp = dataVec->timestamp;
    }
}

HoldPostureErrorCode SignalAIService::HandleAccGyrData(int &frameStartIdx, BufferInfo &bufInfo, SensorBuffer &frame)
{
    long dataNum = GetReadDataNum(bufInfo.curWriteIdx, bufInfo.lastWriteIdx, bufInfo.fifoCount);
    printf(
        "SIGNALAI:Service: lastWriteIdx =%ld, curWriteIdx=%ld, dataNum=%ld",
        bufInfo.lastWriteIdx, bufInfo.curWriteIdx, dataNum);
    long curReadIndex = 0;
    long curBufferIdx = 0;
    SdcDataVec3 *dataVec = nullptr;
    for (long i = 0; i < dataNum; ++i) {  // 读取每个数据
        curReadIndex = BufferIndexWrap(bufInfo.lastWriteIdx + i, bufInfo.fifoCount);
        dataVec = ReadSingleDataByIdx(bufInfo.addrOffset, curReadIndex);
        // 处理acce数据
        curBufferIdx = frame.count;  // buffer当前的指针位置
        if (bufInfo.firstRunFlg == true) {
            // 收到第一组数据初始化滑窗的开始时间和结束时间
            frameStartTimestampNs_ =
                frameStartTimestampNs_ > dataVec->timestamp ? frameStartTimestampNs_ : dataVec->timestamp;
            frameEndTimestampNs_ = frameStartTimestampNs_ + FRAME_DURATION_TIME_MS * TIME_UNIT_MS_TO_NS;
            bufInfo.firstRunFlg = false;
            frameStartIdx = curBufferIdx;
            printf(
                "SIGNALAI:Service:init time frame start = %s, end = %s, FrameStartIdx = %d",
                std::to_string(frameStartTimestampNs_).c_str(), std::to_string(frameEndTimestampNs_).c_str(),
                frameStartIdx);
        }
        // 缓存acce数据到buffer中
        SetSensorBuffer(frame.sensorBuffer, curBufferIdx, dataVec);
        JudgeSampleInterval(curBufferIdx, frame.sensorBuffer);
        frame.count++;
        if (frame.count >= SENSOR_BUFF_LEN) {  // buffer满后从头开始
            frame.count = 0;
        }
    }
    return HoldPostureErrorCode::SUCCESS;
}

DetrendSensorData SignalAIService::GetMean(DetrendSensorData (&sensorData)[SAMPLE_NUM])
{
    DetrendSensorData sum = {0.0, 0.0, 0.0};
    for (int j = 0; j < SAMPLE_NUM; j++) {
        sum.x = sum.x + sensorData[j].x;
        sum.y = sum.y + sensorData[j].y;
        sum.z = sum.z + sensorData[j].z;
    }
    sum.x = sum.x / SAMPLE_NUM;
    sum.y = sum.y / SAMPLE_NUM;
    sum.z = sum.z / SAMPLE_NUM;
    return sum;
}

DetrendSensorData SignalAIService::GetStd(DetrendSensorData (&sensorData)[SAMPLE_NUM], DetrendSensorData &mean)
{
    DetrendSensorData sum = {0.0, 0.0, 0.0};
    if (SAMPLE_NUM <= 1) {
        return sum;
    }
    for (int j = 0; j < SAMPLE_NUM; j++) {
        sum.x += (sensorData[j].x - mean.x) * (sensorData[j].x - mean.x);
        sum.y += (sensorData[j].y - mean.y) * (sensorData[j].y - mean.y);
        sum.z += (sensorData[j].z - mean.z) * (sensorData[j].z - mean.z);
    }
    sum.x = sqrt(sum.x / (SAMPLE_NUM - 1)) + 1e-15;
    sum.y = sqrt(sum.y / (SAMPLE_NUM - 1)) + 1e-15;
    sum.z = sqrt(sum.z / (SAMPLE_NUM - 1)) + 1e-15;
    return sum;
}

void SignalAIService::ZScoreNorm(DetrendSensorData (&detrendSensorData)[SAMPLE_NUM],
    ImuSensorData (&sensorData)[SAMPLE_NUM], DetrendSensorData &mean, DetrendSensorData &std)
{
    for (int i = 0; i < SAMPLE_NUM; i++) {
        sensorData[i].x = (detrendSensorData[i].x - mean.x) / std.x;
        sensorData[i].y = (detrendSensorData[i].y - mean.y) / std.y;
        sensorData[i].z = (detrendSensorData[i].z - mean.z) / std.z;
    }
}

// 获取滑动平均 kernelsize=5 序列前后需要补充2
void SignalAIService::MovingAverage(DetrendSensorData (&data)[SAMPLE_NUM], ImuSensorData (&arr)[SAMPLE_NUM])
{
    int ks = 5;
    int pad = 2;
    data[0].x = arr[0].x - (arr[0].x + arr[0].x + arr[0].x + arr[1].x + arr[2].x) / ks;  // 2表示第3个元素
    data[1].x = arr[1].x - (arr[0].x + arr[0].x + arr[1].x + arr[2].x + arr[3].x) / ks;  // 2 3表示第3 4个元素
    data[SAMPLE_NUM - 2].x = arr[SAMPLE_NUM - 2].x - (arr[SAMPLE_NUM - 4].x + arr[SAMPLE_NUM - 3].x +  // 2 3 4
        arr[SAMPLE_NUM - 2].x + arr[SAMPLE_NUM - 1].x + arr[SAMPLE_NUM - 1].x) / ks;  // 表示倒数第2 3 4个元素
    data[SAMPLE_NUM - 1].x = arr[SAMPLE_NUM - 1].x - (arr[SAMPLE_NUM - 3].x + arr[SAMPLE_NUM - 2].x +  // 2 3为倒数2 3个
        arr[SAMPLE_NUM - 1].x + arr[SAMPLE_NUM - 1].x + arr[SAMPLE_NUM - 1].x) / ks;

    data[0].y = arr[0].y - (arr[0].y + arr[0].y + arr[0].y + arr[1].y + arr[2].y) / ks;  // 2表示第3个元素
    data[1].y = arr[1].y - (arr[0].y + arr[0].y + arr[1].y + arr[2].y + arr[3].y) / ks;  // 2 3表示第3 4个元素
    data[SAMPLE_NUM - 2].y = arr[SAMPLE_NUM - 2].y - (arr[SAMPLE_NUM - 4].y + arr[SAMPLE_NUM - 3].y +  // 2 3 4
        arr[SAMPLE_NUM - 2].y + arr[SAMPLE_NUM - 1].y + arr[SAMPLE_NUM - 1].y) / ks;  // 表示倒数第2 3 4个元素
    data[SAMPLE_NUM - 1].y = arr[SAMPLE_NUM - 1].y - (arr[SAMPLE_NUM - 3].y + arr[SAMPLE_NUM - 2].y +  // 2 3为倒数2 3个
        arr[SAMPLE_NUM - 1].y + arr[SAMPLE_NUM - 1].y + arr[SAMPLE_NUM - 1].y) / ks;

    data[0].z = arr[0].z - (arr[0].z + arr[0].z + arr[0].z + arr[1].z + arr[2].z) / ks;  // 2表示第3个元素
    data[1].z = arr[1].z - (arr[0].z + arr[0].z + arr[1].z + arr[2].z + arr[3].z) / ks;  // 2 3表示第3 4个元素
    data[SAMPLE_NUM - 2].z = arr[SAMPLE_NUM - 2].z - (arr[SAMPLE_NUM - 4].z + arr[SAMPLE_NUM - 3].z +  // 2 3 4
        arr[SAMPLE_NUM - 2].z + arr[SAMPLE_NUM - 1].z + arr[SAMPLE_NUM - 1].z) / ks;  // 表示倒数第2 3 4个元素
    data[SAMPLE_NUM - 1].z = arr[SAMPLE_NUM - 1].z - (arr[SAMPLE_NUM - 3].z + arr[SAMPLE_NUM - 2].z +  // 2 3为倒数2 3个
        arr[SAMPLE_NUM - 1].z + arr[SAMPLE_NUM - 1].z + arr[SAMPLE_NUM - 1].z) / ks;

    DetrendSensorData sum;
    sum.x = arr[0].x + arr[1].x + arr[2].x + arr[3].x + arr[4].x;  // 2 3 4表示第2 3 4个元素
    sum.y = arr[0].y + arr[1].y + arr[2].y + arr[3].y + arr[4].y;  // 2 3 4表示第2 3 4个元素
    sum.z = arr[0].z + arr[1].z + arr[2].z + arr[3].z + arr[4].z;  // 2 3 4表示第2 3 4个元素
    for (int i = 0; i < SAMPLE_NUM - ks + 1; i++) {
        if (i != 0) {
            sum.x = sum.x - arr[i - 1].x + arr[i + ks - 1].x;
            sum.y = sum.y - arr[i - 1].y + arr[i + ks - 1].y;
            sum.z = sum.z - arr[i - 1].z + arr[i + ks - 1].z;
        }
        data[i + pad].x = arr[i + pad].x - sum.x / ks;
        data[i + pad].y = arr[i + pad].y - sum.y / ks;
        data[i + pad].z = arr[i + pad].z - sum.z / ks;
    }
}

HoldPostureErrorCode SignalAIService::Preprocess(int accFrameEndIdx, int gyrFrameEndIdx)
{
    // 取上报的最后一个数据时间戳作为AI计算的最后一个时间戳
    frameEndTimestampNs_ =
        acceFrame_.sensorBuffer[accFrameEndIdx].timestamp < gyroFrame_.sensorBuffer[gyrFrameEndIdx].timestamp
            ? acceFrame_.sensorBuffer[accFrameEndIdx].timestamp
            : gyroFrame_.sensorBuffer[gyrFrameEndIdx].timestamp;
    frameStartTimestampNs_ = frameEndTimestampNs_ - (FRAME_DURATION_TIME_MS + FRAME_EXTRA_MS) * TIME_UNIT_MS_TO_NS;
    accFrameStartIdx_ =
        FindBufferStartIdx(accFrameStartIdx_, accFrameEndIdx, frameStartTimestampNs_, acceFrame_.sensorBuffer);
    gyrFrameStartIdx_ =
        FindBufferStartIdx(gyrFrameStartIdx_, gyrFrameEndIdx, frameStartTimestampNs_, gyroFrame_.sensorBuffer);

    // 找到插值时的初始时间戳
    long long baselineTimestamp;
    if (acceFrame_.sensorBuffer[accFrameStartIdx_].timestamp > gyroFrame_.sensorBuffer[gyrFrameStartIdx_].timestamp) {
        baselineTimestamp = acceFrame_.sensorBuffer[accFrameStartIdx_].timestamp;
    } else {
        baselineTimestamp = gyroFrame_.sensorBuffer[gyrFrameStartIdx_].timestamp;
    }

    auto ret = LinearInterpolation(baselineTimestamp, accFrameStartIdx_, accFrameEndIdx, gyrFrameStartIdx_,
        gyrFrameEndIdx);
    if (ret != HoldPostureErrorCode::SUCCESS) {
        return ret;
    }
    MovingAverage(accDetrendData_, acceInterpolationFrame_.sensorBuffer);
    MovingAverage(gyrDetrendData_, gyroInterpolationFrame_.sensorBuffer);
    DetrendSensorData accMean = GetMean(accDetrendData_);
    DetrendSensorData gyrMean = GetMean(gyrDetrendData_);
    DetrendSensorData accStd = GetStd(accDetrendData_, accMean);
    DetrendSensorData gyrStd = GetStd(gyrDetrendData_, gyrMean);
    ZScoreNorm(accDetrendData_, acceInterpolationFrame_.sensorBuffer, accMean, accStd);
    ZScoreNorm(gyrDetrendData_, gyroInterpolationFrame_.sensorBuffer, gyrMean, gyrStd);

    // 将缓存的buffer数据拷贝到模型输入向量中
    signalAIManager_.GenerateFeature(acceInterpolationFrame_.sensorBuffer, gyroInterpolationFrame_.sensorBuffer,
        orient_);
    return HoldPostureErrorCode::SUCCESS;
}

HoldPostureErrorCode SignalAIService::Postprocess(int &result, int &finalResult)
{
    float modelOutput[MS_AI_OUTPUT_SIZE] = {0.0};  // 推理原始结果
    if (signalAIManager_.Predict(modelOutput)) {
        float score[MS_AI_OUTPUT_SIZE] = {0.0};  // 推理softmax分数
        Softmax(modelOutput, score);
        result = GetSingleHoldResult(score);
        finalResult = GetAccumulatedHoldResult(result);
        printf(
            "SIGNALAI:Service:Predict result = %d, finalResult = %d", result, finalResult);
        return HoldPostureErrorCode::SUCCESS;
    }
    printf("SIGNALAI:Service:Predict fail");
    return HoldPostureErrorCode::PREDICT_FAIL;
}

HoldPostureErrorCode SignalAIService::DecodeSdcHeader(unsigned int &accFifoWriteIdx, unsigned int &gyrFifoWriteIdx)
{
    if (sensorShareAddr_ == nullptr) {
        printf("SIGNALAI:Service:ShareAddr = NULL");
        return HoldPostureErrorCode::SENSOR_SDC_ADDRESS_ERROR;
    }
    // 解析SDC共享内存区域
    SdcDataHeader *accHeader = reinterpret_cast<SdcDataHeader*>(&sensorShareAddr_[accBufInfo_.addrOffset]);
    SdcDataHeader *gyrHeader = reinterpret_cast<SdcDataHeader*>(&sensorShareAddr_[gyrBufInfo_.addrOffset]);
    accFifoWriteIdx = accHeader->fifoWriteIndex;
    gyrFifoWriteIdx = gyrHeader->fifoWriteIndex;
    return HoldPostureErrorCode::SUCCESS;
}

HoldPostureErrorCode SignalAIService::JudgeInfer(int &finalResult)
{
    if (accBufInfo_.firstRunFlg || gyrBufInfo_.firstRunFlg) {
        printf("SIGNALAI:Service: init buffer warm up");
        return HoldPostureErrorCode::SUCCESS;
    }
    int accFrameEndIdx = BufferIndexWrap(acceFrame_.count - 1, SENSOR_BUFF_LEN);
    int gyrFrameEndIdx = BufferIndexWrap(gyroFrame_.count - 1, SENSOR_BUFF_LEN);
    if (acceFrame_.sensorBuffer[accFrameEndIdx].timestamp - acceFrame_.sensorBuffer[accFrameStartIdx_].timestamp >=
        (FRAME_DURATION_TIME_MS + FRAME_EXTRA_MS) * TIME_UNIT_MS_TO_NS &&
        gyroFrame_.sensorBuffer[gyrFrameEndIdx].timestamp - gyroFrame_.sensorBuffer[gyrFrameStartIdx_].timestamp >=
        (FRAME_DURATION_TIME_MS + FRAME_EXTRA_MS) * TIME_UNIT_MS_TO_NS &&
        !warmUpEnd_) {
        warmUpEnd_ = true;
        printf("SIGNALAI:Service:warm up end");
    }
    if (warmUpEnd_) {
        auto ret = Preprocess(accFrameEndIdx, gyrFrameEndIdx);
        if (ret != HoldPostureErrorCode::SUCCESS) {
            return ret;
        }
        int singleResult = -1;
        if (Postprocess(singleResult, finalResult) != HoldPostureErrorCode::SUCCESS) {
            printf("SIGNALAI:Service:predict error");
            return HoldPostureErrorCode::PREDICT_FAIL;
        }
        UpdatePrintInfo(acceFrame_.sensorBuffer[accFrameEndIdx].timestamp,
            gyroFrame_.sensorBuffer[gyrFrameEndIdx].timestamp, singleResult, finalResult);
    } else {
        printf("SIGNALAI:Service:warm up");
    }
    return HoldPostureErrorCode::SUCCESS;
}

// 根据上一次写指针和当前写指针的时间差判断可以滑窗的次数
int SignalAIService::GetSdcCacheSlideNum(long long &startTimestamp, long long &endTimestamp, BufferInfo &bufInfo)
{
    SdcDataVec3 *dataVec = ReadSingleDataByIdx(bufInfo.addrOffset, bufInfo.curWriteIdx);
    endTimestamp = dataVec->timestamp;

    dataVec = ReadSingleDataByIdx(bufInfo.addrOffset, bufInfo.lastWriteIdx);
    startTimestamp = dataVec->timestamp;
    // 计算sdc缓存的数据量
    int frameSlideNum = accumulatedNum_;
    long long timeDiff = endTimestamp - startTimestamp - FRAME_DURATION_TIME_MS * TIME_UNIT_MS_TO_NS;
    if (timeDiff < 0) {
        return 0;  // 缓存的数据不够一次滑窗
    }
    if (timeDiff > frameSlideTimeMs_ * TIME_UNIT_MS_TO_NS * (accumulatedNum_ - 1)) {
        return frameSlideNum;
    }
    frameSlideNum = timeDiff / (frameSlideTimeMs_ * TIME_UNIT_MS_TO_NS) + 1;
    return frameSlideNum;
}

// 获取每次滑窗时窗口最后一个元素的索引
void SignalAIService::GetFrameSlideIdx(long long startTimestamp, long long endTimestamp, std::vector<long> &idxList,
    BufferInfo &bufInfo, int frameSlideNum)
{
    long offset = 0;
    long dataNum = GetReadDataNum(bufInfo.curWriteIdx, bufInfo.lastWriteIdx, bufInfo.fifoCount);
    SdcDataVec3 *dataVec;
    for (int i = 0; i < frameSlideNum; ++i) {
        for (long j = offset; j < dataNum; ++j) {
            long idx = BufferIndexWrap(bufInfo.curWriteIdx - j, bufInfo.fifoCount);
            dataVec = ReadSingleDataByIdx(bufInfo.addrOffset, idx);
            if (dataVec->timestamp <= endTimestamp) {
                offset = j;
                idxList.push_back(idx);
                break;
            }
        }
        endTimestamp = endTimestamp - frameSlideTimeMs_ * TIME_UNIT_MS_TO_NS;
    }
    // 获取第一个元素的索引
    for (long j = offset; j < dataNum; ++j) {
        long idx = BufferIndexWrap(bufInfo.curWriteIdx - j, bufInfo.fifoCount);
        dataVec = ReadSingleDataByIdx(bufInfo.addrOffset, idx);
        if (dataVec->timestamp <= startTimestamp) {
            bufInfo.lastWriteIdx = idx;
            break;
        }
    }
}

HoldPostureErrorCode SignalAIService::HandleMultiShotWithCache(long long accEndTimestamp, long long gyrEndTimestamp,
    int frameSlideNum, int &finalResult)
{
    HoldPostureErrorCode ret = HoldPostureErrorCode::SUCCESS;
    std::vector<long> accIdxList;
    std::vector<long> gyrIdxList;
    long long accStartTimestamp = accEndTimestamp - FRAME_DURATION_TIME_MS * TIME_UNIT_MS_TO_NS -
                        (frameSlideNum - 1) * frameSlideTimeMs_ * TIME_UNIT_MS_TO_NS;
    GetFrameSlideIdx(accStartTimestamp, accEndTimestamp, accIdxList, accBufInfo_, frameSlideNum);
    long long gyrStartTimestamp = gyrEndTimestamp - FRAME_DURATION_TIME_MS * TIME_UNIT_MS_TO_NS -
                        (frameSlideNum - 1) * frameSlideTimeMs_ * TIME_UNIT_MS_TO_NS;
    GetFrameSlideIdx(gyrStartTimestamp, gyrEndTimestamp, gyrIdxList, gyrBufInfo_, frameSlideNum);
    if (accIdxList.size() != static_cast<size_t>(frameSlideNum) ||
        gyrIdxList.size() != static_cast<size_t>(frameSlideNum)) {
        return HoldPostureErrorCode::SUCCESS;  // 返回success让AI继续后续的计算
    }
    int warmUpResult = -1;
    for (int i = 0; i < frameSlideNum; ++i) {
        accBufInfo_.curWriteIdx = accIdxList[frameSlideNum - 1 - i];
        gyrBufInfo_.curWriteIdx = gyrIdxList[frameSlideNum - 1 - i];
        printf("SIGNALAI:Service:i=%d, accCurReadIdx=%ld, gyrCurReadIdx=%ld",
            frameSlideNum - 1 - i, accBufInfo_.curWriteIdx, gyrBufInfo_.curWriteIdx);
        ret = HandleAccGyrData(accFrameStartIdx_, accBufInfo_, acceFrame_);
        if (ret != HoldPostureErrorCode::SUCCESS) {
            return ret;
        }
        ret = HandleAccGyrData(gyrFrameStartIdx_, gyrBufInfo_, gyroFrame_);
        if (ret != HoldPostureErrorCode::SUCCESS) {
            return ret;
        }
        int accFrameEndIdx = BufferIndexWrap(acceFrame_.count - 1, SENSOR_BUFF_LEN);
        int gyrFrameEndIdx = BufferIndexWrap(gyroFrame_.count - 1, SENSOR_BUFF_LEN);
        ret = Preprocess(accFrameEndIdx, gyrFrameEndIdx);
        if (ret != HoldPostureErrorCode::SUCCESS) {
            return ret;
        }
        int singleResult = -1;
        ret = Postprocess(singleResult, warmUpResult);
        if (ret != HoldPostureErrorCode::SUCCESS) {
            return ret;
        }
        UpdatePrintInfo(acceFrame_.sensorBuffer[accFrameEndIdx].timestamp,
            gyroFrame_.sensorBuffer[gyrFrameEndIdx].timestamp, singleResult, finalResult);
        accBufInfo_.lastWriteIdx = accBufInfo_.curWriteIdx;
        gyrBufInfo_.lastWriteIdx = gyrBufInfo_.curWriteIdx;
    }
    finalResult = warmUpResult;
    printf("SIGNALAI:Service:first run result=%d", warmUpResult);
    return ret;
}

// 判断SDC共享内存缓存的数据是否足够AI计算
HoldPostureErrorCode SignalAIService::HandleFirstRunWithCache(int &finalResult)
{
    HoldPostureErrorCode ret = HoldPostureErrorCode::SUCCESS;
    time_t now = std::time(nullptr);
    long long accStartTimestamp = 0;
    long long accEndTimestamp = 0;
    int accFrameSlideNum =
        GetSdcCacheSlideNum(accStartTimestamp, accEndTimestamp, accBufInfo_);
    long long gyrStartTimestamp = 0;
    long long gyrEndTimestamp = 0;
    int frameSlideNum =
        GetSdcCacheSlideNum(gyrStartTimestamp, gyrEndTimestamp, gyrBufInfo_);
    printf("SIGNALAI:Service:Slide a=%d, g=%d", accFrameSlideNum, frameSlideNum);
    frameSlideNum = accFrameSlideNum < frameSlideNum ? accFrameSlideNum : frameSlideNum;
    if (frameSlideNum < 1 && (now - lastFifoWriteIdxSetTime_ <= WARM_UP_TIME_INTERVAL)) {  // 缓存的数据量不足一次计算
        ret = HandleAccGyrData(accFrameStartIdx_, accBufInfo_, acceFrame_);
        if (ret != HoldPostureErrorCode::SUCCESS) {
            return ret;
        }
        ret = HandleAccGyrData(gyrFrameStartIdx_, gyrBufInfo_, gyroFrame_);
        if (ret != HoldPostureErrorCode::SUCCESS) {
            return ret;
        }
        accBufInfo_.lastWriteIdx = accBufInfo_.curWriteIdx;
        gyrBufInfo_.lastWriteIdx = gyrBufInfo_.curWriteIdx;
        printf("SIGNALAI:Service:no enough data for one-shot");
        return ret;
    } else if (now - lastFifoWriteIdxSetTime_ > WARM_UP_TIME_INTERVAL) {  // 缓存的数据足够多次计算
        frameSlideNum = accumulatedNum_;
        accBufInfo_.lastWriteIdx = BufferIndexWrap(accBufInfo_.curWriteIdx + 1, accBufInfo_.fifoCount);  // 向前可回溯的最远索引
        gyrBufInfo_.lastWriteIdx = BufferIndexWrap(gyrBufInfo_.curWriteIdx + 1, gyrBufInfo_.fifoCount);
    }
    printf("SIGNALAI:Service:get enough data for multi-shot slide=%d", frameSlideNum);
    return HandleMultiShotWithCache(accEndTimestamp, gyrEndTimestamp, frameSlideNum, finalResult);
}

HoldPostureErrorCode SignalAIService::DecodeMemory(int &finalResult)
{
    HoldPostureErrorCode ret = DecodeSdcHeader(accWriteIdxUnwrap_, gyrWriteIdxUnwrap_);
    if (ret != HoldPostureErrorCode::SUCCESS) {
        return ret;
    }
    // sensor数据不更新
    if (accWriteIdxUnwrap_ == lastAccWriteIdxUnWrap_ || gyrWriteIdxUnwrap_ == lastGyrWriteIdxUnWrap_) {
        printf("SIGNALAI:Service:sensor data not update, "
            "accWriteIdx=%d,last=%u,gyrWriteIdx=%d,last=%d",
            accWriteIdxUnwrap_, lastAccWriteIdxUnWrap_, gyrWriteIdxUnwrap_, lastGyrWriteIdxUnWrap_);
        return HoldPostureErrorCode::SENSOR_DATA_NOT_UPDATE;
    }
    lastAccWriteIdxUnWrap_ = accWriteIdxUnwrap_;
    lastGyrWriteIdxUnWrap_ = gyrWriteIdxUnwrap_;
    accBufInfo_.curWriteIdx = BufferIndexWrap(accWriteIdxUnwrap_ - 1, accBufInfo_.fifoCount);  // 取当前写指针的前一个防止当前还未写入
    gyrBufInfo_.curWriteIdx = BufferIndexWrap(gyrWriteIdxUnwrap_ - 1, gyrBufInfo_.fifoCount);

    recorder_.SetCurWriteIdx(accWriteIdxUnwrap_, gyrWriteIdxUnwrap_, false);

    if (accBufInfo_.firstRunFlg || gyrBufInfo_.firstRunFlg) {  // 第一次启动计算
        printf(
            "SIGNALAI:Service:first run start. lastAcc=%ld, curAcc=%ld, lastGyr=%ld, "
            "curGyr=%ld", accBufInfo_.lastWriteIdx, accBufInfo_.curWriteIdx, gyrBufInfo_.lastWriteIdx,
            gyrBufInfo_.curWriteIdx);
        return HandleFirstRunWithCache(finalResult);
    }
    // 非首次启动
    ret = HandleAccGyrData(accFrameStartIdx_, accBufInfo_, acceFrame_);
    if (ret != HoldPostureErrorCode::SUCCESS) {
        return ret;
    }
    accBufInfo_.lastWriteIdx = accBufInfo_.curWriteIdx;
    ret = HandleAccGyrData(gyrFrameStartIdx_, gyrBufInfo_, gyroFrame_);
    if (ret != HoldPostureErrorCode::SUCCESS) {
        return ret;
    }
    gyrBufInfo_.lastWriteIdx = gyrBufInfo_.curWriteIdx;
    return JudgeInfer(finalResult);
}

void SignalAIService::SetLastFifoWriteIdx(unsigned int accLastWriteIdx, unsigned int gyrLastWriteIdx,
    unsigned int accFifoCount, unsigned int gyrFifoCount, time_t fifoWriteIdxSetTime)
{
    accBufInfo_.fifoCount = accFifoCount;
    gyrBufInfo_.fifoCount = gyrFifoCount;
    recorder_.PreSetInfo(accFifoCount, gyrFifoCount, accLastWriteIdx, gyrLastWriteIdx);
    lastAccWriteIdxUnWrap_ = accLastWriteIdx;
    lastGyrWriteIdxUnWrap_ = gyrLastWriteIdx;
    accBufInfo_.lastWriteIdx = BufferIndexWrap(accLastWriteIdx, accBufInfo_.fifoCount);
    gyrBufInfo_.lastWriteIdx = BufferIndexWrap(gyrLastWriteIdx, gyrBufInfo_.fifoCount);
    lastFifoWriteIdxSetTime_ = fifoWriteIdxSetTime;
    printf("SIGNALAI:Service:SetLastFifoWriteIdx lastAccWriteIdxUnWrap=%d, lastGyrWriteIdxUnWrap=%d,"
        "accFifoCount=%u, gyrFifoCount=%u.",
        lastAccWriteIdxUnWrap_, lastGyrWriteIdxUnWrap_, accFifoCount, gyrFifoCount);
}

void SignalAIService::ReleaseAi()
{
    printf("SIGNALAI:Service:ReleaseModel start.");
    accFrameStartIdx_ = 0;
    gyrFrameStartIdx_ = 0;
    frameStartTimestampNs_ = 0;
    frameEndTimestampNs_ = 0;
    lastAccWriteIdxUnWrap_ = 0;
    lastGyrWriteIdxUnWrap_ = 0;
    lastFifoWriteIdxSetTime_ = 0;
    memset_s(&acceFrame_, sizeof(SensorBuffer), 0, sizeof(SensorBuffer));
    memset_s(&gyroFrame_, sizeof(SensorBuffer), 0, sizeof(SensorBuffer));
    holdResultQue_.clear();
    logVec_.idx = 0;
    lastHoldPostureIdx_ = -1;
    warmUpEnd_ = false;
    accBufInfo_ = {-1, 0, true, 0, -1};
    gyrBufInfo_ = {-1, 0, true, 0, -1};
    signalAIManager_.ReleaseModel();
    recorder_.SetCurWriteIdx(accWriteIdxUnwrap_, gyrWriteIdxUnwrap_, true);
    printf("SIGNALAI:Service:ReleaseModel end.");
}

void SignalAIService::UpdatePrintInfo(long long accTime, long long gyrTime, int result, int finalResult)
{
    LogPrintInfo info = {accTime, gyrTime, result, finalResult, orient_};
    if (logVec_.idx >= MAX_LOG_PRINT_NUM) {  // 2表示打印2倍投票前的输出
        logVec_.idx = 0;
    }
    logVec_.printInfo[logVec_.idx] = info;
    logVec_.idx++;
    if (finalResult != lastHoldResult_) {
        for (int i = 0; i < MAX_LOG_PRINT_NUM; ++i) {  // 2表示打印2倍投票前的输出
            printf(
                "SIGNALAI:Service: atime=%lld,gtime=%lld,%d,%d,%d",
                logVec_.printInfo[i].accTimestamp, logVec_.printInfo[i].gyrTimestamp,
                logVec_.printInfo[i].singleResult, logVec_.printInfo[i].finalResult, logVec_.printInfo[i].orient);
        }
        lastHoldResult_ = finalResult;
    }
}

}  // namespace Telephony
}  // namespace OHOS