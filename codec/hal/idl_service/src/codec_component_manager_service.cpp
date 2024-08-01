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

#include "codec_component_manager_service.h"
#include <hdf_base.h>
#include <hitrace_meter.h>
#include "codec_component_config.h"
#include "codec_component_service.h"
#include "codec_log_wrapper.h"
#include "component_node.h"
#include "codec_dfx_service.h"
#include "codec_death_recipient.h"
namespace OHOS {
namespace HDI {
namespace Codec {
namespace V3_0 {
sptr<CodecComponentManagerService> g_codecManagerService = sptr<CodecComponentManagerService>();
std::once_flag m_serviceFlag;
using OHOS::Codec::Omx::ComponentNode;
extern "C" ICodecComponentManager *CodecComponentManagerImplGetInstance(void)
{
    std::call_once(m_serviceFlag, [] {
        g_codecManagerService = sptr<CodecComponentManagerService>(new CodecComponentManagerService());
        CodecDfxService::GetInstance().SetComponentManager(g_codecManagerService);
        OHOS::Codec::Omx::CodecComponentConfig::GetInstance()->CodecCompCapabilityInit();
    });
    return g_codecManagerService;
}

CodecComponentManagerService::CodecComponentManagerService() : componentId_(0)
{
    resourceNode_.name = nullptr;
    resourceNode_.hashValue = 0;
    resourceNode_.attrData = nullptr;
    resourceNode_.parent = nullptr;
    resourceNode_.child = nullptr;
    resourceNode_.sibling = nullptr;
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

bool CodecComponentManagerService::JudgePassThrouth(void)
{
    uint32_t remotePid = static_cast<uint32_t>(HdfRemoteGetCallingPid());
    uint32_t curPid = static_cast<uint32_t>(getpid());
    return remotePid == curPid;
}

int32_t CodecComponentManagerService::CreateComponent(sptr<ICodecComponent> &component, uint32_t &componentId,
                                                      const std::string &compName, int64_t appData,
                                                      const sptr<ICodecCallback> &callbacks)
{
    HITRACE_METER_NAME(HITRACE_TAG_HDF, "HDFCodecCreateComponent");
    CODEC_LOGD("compName[%{public}s]", compName.c_str());
    CHECK_AND_RETURN_RET_LOG(callbacks != nullptr, HDF_ERR_INVALID_PARAM, "callbacks is null");
    std::shared_ptr<ComponentNode> node = std::make_shared<ComponentNode>(callbacks, appData, mgr_);
    auto err = node->OpenHandle(compName);
    if (err != HDF_SUCCESS) {
        CODEC_LOGE("OpenHandle faled, err[%{public}d]", err);
        node = nullptr;
        return err;
    }

    sptr<ICodecComponent> codecComponent(new CodecComponentService(node, mgr_, compName));
    std::unique_lock<std::mutex> autoLock(mutex_);
    componentId = GetNextComponentId();
    componentMap_.emplace(std::make_pair(componentId, codecComponent));
    component = codecComponent;
    CODEC_LOGI("componentId[%{public}d]", componentId);
    if (!JudgePassThrouth()) {
        RegisterDeathRecipientService(callbacks, componentId, this);
    }
    return HDF_SUCCESS;
}

int32_t CodecComponentManagerService::DestroyComponent(uint32_t componentId)
{
    HITRACE_METER_NAME(HITRACE_TAG_HDF, "HDFCodecDestroyComponent");
    std::unique_lock<std::mutex> autoLock(mutex_);
    CODEC_LOGI("componentId[%{public}d]", componentId);
    auto iter = componentMap_.find(componentId);
    if (iter == componentMap_.end() || iter->second == nullptr) {
        CODEC_LOGE("can not find component service by componentId[%{public}d]", componentId);
        return HDF_ERR_INVALID_PARAM;
    }
    componentMap_.erase(iter);
    RemoveMapperOfDestoryedComponent(componentId);
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

void CodecComponentManagerService::GetManagerMap(std::map<uint32_t, sptr<ICodecComponent>> &dumpMap)
{
    dumpMap = componentMap_;
}
}  // namespace V3_0
}  // namespace Codec
}  // namespace HDI
}  // namespace OHOS
