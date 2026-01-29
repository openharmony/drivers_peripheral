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

#ifndef SIGNALAI_MANAGER_H
#define SIGNALAI_MANAGER_H

#include "sensor_sdc_model.h"
#include <string>

namespace OHOS {
namespace Telephony {

class SignalAIManager {
public:
    // 初始化模型
    bool InitModel(const std::string& filePath, const std::vector<std::string>& validFiles);

    // 释放模型
    void ReleaseModel(void);

    // 模型输入tensor赋值
    void GenerateFeature(ImuSensorData (&accInterpBuffer)[SAMPLE_NUM],
        ImuSensorData (&gyrInterpBuffer)[SAMPLE_NUM], uint32_t orient);

    // 模型推理
    bool Predict(float (&output)[MS_AI_OUTPUT_SIZE]);

private:
    bool IsValidPath(const std::string& filePath, const std::vector<std::string>& validFiles);
    bool LoadModel(const std::string& filePath, const std::vector<std::string>& validFiles);

    NnModel aiModel_;
    size_t modelBufSize_ = 0;
    float featureInput_[FEATURE_LEN] = {0.0};
    float orientInput_[ORIENT_LEN] = {0.0};
    SignalAIModel signalAIModel_;
};

}  // Telephony
}  // OHOS
#endif  // SIGNALAI_MANAGER_H