/*
 * Copyright 2022 Shenzhen Kaihong DID Co., Ltd.
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

#include "codec_component_manager_service.h"
#include <hdf_base.h>
#include "codec_component_config.h"
#include "codec_component_service.h"
#include "codec_log_wrapper.h"
#include "component_node.h"
namespace OHOS {
namespace HDI {
namespace Codec {
namespace V1_0 {
using OHOS::Codec::Omx::ComponentNode;
extern "C" ICodecComponentManager *CodecComponentManagerImplGetInstance(void)
{
    return new (std::nothrow) CodecComponentManagerService();
}

CodecComponentManagerService::CodecComponentManagerService() : componentId_(0)
{
    mgr_ = std::make_shared<OHOS::Codec::Omx::ComponentMgr>();
}

int32_t CodecComponentManagerService::GetComponentNum(int32_t &count)
{
    return OHOS::Codec::Omx::CodecComponentConfig::GetInstance()->GetComponentNum(count);
}

int32_t CodecComponentManagerService::GetComponentCapabilityList(std::vector<CodecCompCapability> &capList,
                                                                 int32_t count)
{
    return OHOS::Codec::Omx::CodecComponentConfig::GetInstance()->GetComponentCapabilityList(capList, count);
}

int32_t CodecComponentManagerService::CreateComponent(sptr<ICodecComponent> &component, uint32_t &componentId,
                                                      const std::string &compName, int64_t appData,
                                                      const sptr<ICodecCallback> &callbacks)
{
    CODEC_LOGD("compName[%{public}s]", compName.c_str());
    std::shared_ptr<ComponentNode> node = std::make_shared<ComponentNode>(callbacks, appData, mgr_);
    auto err = node->OpenHandle(compName);
    if (err != HDF_SUCCESS) {
        CODEC_LOGE("OpenHandle faled, err[%{public}d]", err);
        node = nullptr;
        return err;
    }

    sptr<ICodecComponent> codecComponent = new CodecComponentService(node);
    std::unique_lock<std::mutex> autoLock(mutex_);
    componentId = GetNextComponentId();
    componentMap_.emplace(std::make_pair(componentId, codecComponent));
    component = codecComponent;
    CODEC_LOGD("componentId[%{public}d]", componentId);
    return HDF_SUCCESS;
}

int32_t CodecComponentManagerService::DestoryComponent(uint32_t componentId)
{
    CODEC_LOGD("componentId[%{public}d]", componentId);
    auto iter = componentMap_.find(componentId);
    if (iter == componentMap_.end() || iter->second == nullptr) {
        CODEC_LOGE("can not find component service by componentId[%{public}d]", componentId);
        return HDF_ERR_INVALID_PARAM;
    }
    std::unique_lock<std::mutex> autoLock(mutex_);
    componentMap_.erase(iter);
    iter->second = nullptr;
    return HDF_SUCCESS;
}

uint32_t CodecComponentManagerService::GetNextComponentId(void)
{
    uint32_t tempId = 0;
    do {
        tempId = ++componentId_;
    } while (componentMap_.find(tempId) != componentMap_.end());
    return tempId;
}

void CodecComponentManagerService::LoadCapabilityData(const DeviceResourceNode &node)
{
    resourceNode_ = node;
}
}  // namespace V1_0
}  // namespace Codec
}  // namespace HDI
}  // namespace OHOS
