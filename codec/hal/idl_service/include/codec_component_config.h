/*
 * Copyright (c) 2022 Shenzhen Kaihong DID Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef CODEC_CONFIG_H
#define CODEC_CONFIG_H
#include <refbase.h>
#include "v3_0/codec_types.h"
#include "device_resource_if.h"
using OHOS::HDI::Codec::V3_0::CodecCompCapability;
namespace OHOS {
namespace Codec {
namespace Omx {
typedef struct {
    std::string attrName;
    int32_t &value;
    uint32_t defaultValue;
} ConfigUintNodeAttr;
typedef struct {
    std::string attrName;
    std::vector<int32_t> &vec;
} ConfigUintArrayNodeAttr;

class CodecComponentConfig {
public:
    ~CodecComponentConfig() = default;
    static CodecComponentConfig *GetInstance();
    void Init(const DeviceResourceNode &node);
    int32_t CodecCompCapabilityInit();
    int32_t GetComponentNum(int32_t &count);
    int32_t GetComponentCapabilityList(std::vector<CodecCompCapability> &capList, int32_t count);

protected:
    CodecComponentConfig();

private:
    int32_t GetGroupCapabilities(const std::string &nodeName);
    int32_t GetOneCapability(const struct DeviceResourceIface &iface, const struct DeviceResourceNode &childNode,
                             CodecCompCapability &cap, bool isVideoGroup);
    int32_t GetMiscOfCapability(const struct DeviceResourceIface &iface, const struct DeviceResourceNode &childNode,
                                CodecCompCapability &cap);
    int32_t GetUintTableConfig(const struct DeviceResourceIface &iface, const struct DeviceResourceNode &node,
                               ConfigUintArrayNodeAttr &attr);
    int32_t GetMaskedConfig(const struct DeviceResourceIface &iface, const struct DeviceResourceNode &node,
                            const std::string &attrName, uint32_t &mask);
    int32_t GetAudioPortCapability(const struct DeviceResourceIface &iface, const struct DeviceResourceNode &childNode,
                                   CodecCompCapability &cap);
    int32_t GetVideoPortCapability(const struct DeviceResourceIface &iface, const struct DeviceResourceNode &childNode,
                                   CodecCompCapability &cap);
    int32_t GetVideoPortFeature(const struct DeviceResourceIface &iface, const struct DeviceResourceNode &childNode,
                                   CodecCompCapability &cap);

private:
    DeviceResourceNode node_;
    std::vector<CodecCompCapability> capList_;
    static CodecComponentConfig config_;
};
}  // namespace Omx
}  // namespace Codec
}  // namespace OHOS
#endif  // CODEC_CONFIG_H