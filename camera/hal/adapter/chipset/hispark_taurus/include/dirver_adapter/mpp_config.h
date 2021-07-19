/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#ifndef HOS_CAMERA_MPP_CONFIG_H
#define HOS_CAMERA_MPP_CONFIG_H

#include <string>
#include <vector>
#include "device_resource_if.h"
#include "hal_comm.h"
#include "camera.h"

namespace OHOS::Camera {
using NodeInfo = struct _NodeInfo {
    std::string name;
};

class MppConfig {
public:
    MppConfig(const std::string &pathName);
    virtual ~MppConfig();

public:
    RetCode Init(InitParam_E &initParam);
    void SetHcsPathName(const std::string &pathName);

private:
    RetCode DealHcsData(InitParam_E &initParam);
    void DealIspConfig(InitParam_E &initParam, const struct DeviceResourceNode &node);
    void DealDevConfig(InitParam_E &initParam, const struct DeviceResourceNode &node);
    void DealMipiConfig(InitParam_E &initParam, const struct DeviceResourceNode &node);
    RetCode DealVbConfig(InitParam_E &initParam, const struct DeviceResourceNode &node);
    RetCode DealVencConfig(InitParam_E &initParam, const struct DeviceResourceNode &node);
    RetCode DealVpssConfig(InitParam_E &initParam, const struct DeviceResourceNode &node);
    RetCode DealViPipeConfig(InitParam_E &initParam, const struct DeviceResourceNode &node);
    uint32_t GetValue(const struct DeviceResourceNode &node, const char *attrName);
    RetCode DealViChnConfig(InitParam_E &initParam, const struct DeviceResourceNode &node, int32_t pipeNum);

private:
    std::string pathName_;
    DeviceResourceIface *devResInstance_;
    const struct DeviceResourceNode *rootNode_;
};
} /* namespace OHOS::CameraHost */
#endif /* HOS_CAMERA_MPP_CONFIG_H */
