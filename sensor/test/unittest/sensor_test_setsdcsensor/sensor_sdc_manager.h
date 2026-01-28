/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 * Description: ai hold posture sensor process.
 * Create: 2025-02-06
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