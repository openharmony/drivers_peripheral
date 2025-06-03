/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef CODEC_IMAGE_CONFIG_H
#define CODEC_IMAGE_CONFIG_H
#include <refbase.h>
#include "device_resource_if.h"
#include "v2_1/codec_image_type.h"
namespace OHOS {
namespace HDI {
namespace Codec {
namespace Image {
namespace V2_1 {
struct ConfigUintNodeAttr {
    std::string attrName;
    uint32_t &value;
    uint32_t defaultValue;
} ;
struct ConfigUintArrayNodeAttr {
    std::string attrName;
    std::vector<uint32_t> &vec;
} ;

class CodecImageConfig {
public:
    ~CodecImageConfig() = default;
    static CodecImageConfig *GetInstance();
    void Init(const struct DeviceResourceNode &node);
    int32_t GetImageCapabilityList(std::vector<CodecImageCapability> &capList);

protected:
    CodecImageConfig();

private:
    int32_t GetGroupCapabilities(const std::string &nodeName);
    int32_t GetOneCapability(const struct DeviceResourceIface &iface, const struct DeviceResourceNode &childNode,
                             CodecImageCapability &cap);
    int32_t GetUintTableConfig(const struct DeviceResourceIface &iface, const struct DeviceResourceNode &node,
                               ConfigUintArrayNodeAttr &attr);

private:
    struct DeviceResourceNode node_;
    std::vector<CodecImageCapability> capList_;
    static CodecImageConfig config_;
};
} // V2_1
} // Image
} // Codec
} // HDI
} // OHOS
#endif  // CODEC_IMAGE_CONFIG_H
