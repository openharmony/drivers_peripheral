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

#ifndef SIGNALAI_MODEL_H
#define SIGNALAI_MODEL_H

#include <memory>
#include <cstddef.h>
#include <cstdbool.h>
#include "ms_header_c.h"

namespace OHOS {
namespace Telephony {

constexpr int SAMPLE_NUM = 50;  // 输入sensor数据个数
constexpr int FEATURE_DIM = 6;
constexpr int FEATURE_LEN = SAMPLE_NUM * FEATURE_DIM;
constexpr int ORIENT_LEN = 4;
constexpr int MS_AI_OUTPUT_SIZE = 13;
constexpr int SENSOR_BUFF_LEN = 600;
constexpr int INPUT_TENSOR_NUM = 2;  // 模型输入的Tensor个数
constexpr int OUTPUT_TENSOR_NUM = 1;  // 模型输出的Tensor个数

typedef struct {
    long long timestamp; // ms
    double x;
    double y;
    double z;
} ImuSensorData; // IMU data include x axis, y axis, z axis

typedef struct {
    double x;
    double y;
    double z;
} DetrendSensorData; // IMU data include x axis, y axis, z axis

typedef struct {
    ImuSensorData sensorBuffer[SENSOR_BUFF_LEN]; // at most store 600 sensor data
    int count;
} SensorBuffer; // sensor buffer include IMU data array, count of data

typedef struct {
    ImuSensorData sensorBuffer[SAMPLE_NUM]; // at most store 100 sensor data
    int count;
} SensorInterpBuffer; // sensor buffer include IMU data array, count of data

typedef struct NnModel_ {
    std::unique_ptr<char[]> bufferModel;
    bool modelLoadFlag; // false-not loaded, true-loaded
} NnModel; // model struct

class SignalAIModel {
public:
    // 推理模型
    bool ExecuteAiModel(float (&featureInput)[FEATURE_LEN], float (&orientInput)[ORIENT_LEN],
        float (&result)[MS_AI_OUTPUT_SIZE]);

    // 加载模型
    bool LoadAiModel(char *modelBuffer, size_t total);

    // 释放模型
    void ReleaseAiModel();

private:
    bool GetAiInputVector(TensorInfo inputs, float (&featureInput)[FEATURE_LEN], float (&orientInput)[ORIENT_LEN]);
    bool CopyAiResult(Tensor handle, float (&target)[MS_AI_OUTPUT_SIZE]);
    bool GetAiOutputVector(TensorInfo outputs, float (&result)[MS_AI_OUTPUT_SIZE]);
    void ReleaseAiContext();

    Model aiModel_ = nullptr;
    Context context_ = nullptr;
};

}  // Telephony
}  // OHOS
#endif  // SIGNALAI_MODEL_H
