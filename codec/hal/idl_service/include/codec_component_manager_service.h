/*
 * Copyright (c) 2022-2023 Shenzhen Kaihong DID Co., Ltd.
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

#ifndef OHOS_HDI_CODEC_V4_0_CODECCOMPONENTMANAGERSERVICE_H
#define OHOS_HDI_CODEC_V4_0_CODECCOMPONENTMANAGERSERVICE_H

#include <map>
#include <mutex>
#include <hdf_remote_service.h>
#include "device_resource_if.h"
#include "v4_0/icodec_component.h"
#include "v4_0/icodec_component_manager.h"
#include "component_mgr.h"
namespace OHOS {
namespace HDI {
namespace Codec {
namespace V4_0 {
class CodecComponentManagerService : public ICodecComponentManager {
public:
    CodecComponentManagerService();
    virtual ~CodecComponentManagerService() = default;
    int32_t GetComponentNum(int32_t &count) override;
    int32_t GetComponentCapabilityList(std::vector<CodecCompCapability> &capList, int32_t count) override;
    int32_t CreateComponent(sptr<ICodecComponent> &component, uint32_t &componentId, const std::string &compName,
                            int64_t appData, const sptr<ICodecCallback> &callbacks) override;
    int32_t DestroyComponent(uint32_t componentId) override;
    void LoadCapabilityData(const DeviceResourceNode &node);
    void GetManagerMap(std::map<uint32_t, sptr<ICodecComponent>> &dumpMap);
    bool JudgePassThrouth(void);
private:
    uint32_t GetNextComponentId(void);

private:
    std::map<uint32_t, sptr<ICodecComponent>> componentMap_;
    uint32_t componentId_;
    std::mutex mutex_;
    DeviceResourceNode resourceNode_;
    std::shared_ptr<OHOS::Codec::Omx::ComponentMgr> mgr_;
};
}  // namespace V4_0
}  // namespace Codec
}  // namespace HDI
}  // namespace OHOS

#endif  // OHOS_HDI_CODEC_V4_0_CODECCOMPONENTMANAGERSERVICE_H