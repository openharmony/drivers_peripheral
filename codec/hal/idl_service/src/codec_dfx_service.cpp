/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "codec_log_wrapper.h"
#include "codec_dfx_service.h"

namespace OHOS {
namespace HDI {
namespace Codec {
namespace V1_0 {
#define ARGV_FLAG 1
CodecDfxService CodecDfxService::dfxInstance_;
uint32_t CodecDfxService::BuffCount_i;
uint32_t CodecDfxService::BuffCount_j;
uint32_t CodecDfxService::portIndex_i;
uint32_t CodecDfxService::portIndex_j;
std::shared_ptr<OHOS::Codec::Omx::ComponentNode> CodecDfxService::dumpNode;

void CodecDfxService::GetBuffCount()
{
    auto iter = dumpNode->GetBufferMapCount().begin();
    portIndex_i = iter->second;
    while (iter != dumpNode->GetBufferMapCount().end()) {
        if (iter->second == portIndex_i) {
            BuffCount_i++;
        } else {
            portIndex_j = iter->second;
            BuffCount_j++;
        }
        iter++;
    }
}

int32_t CodecDfxService::GetCodecComponentListInfo(struct HdfSBuf *reply)
{
    CodecStateType state;
    CodecComponentService *componentService;
    std::map<uint32_t, sptr<ICodecComponent>> dumpMap = {};

    GetInstance().managerService_->GetManagerMap(dumpMap);
    if (dumpMap.empty()) {
        CODEC_LOGE("get manager map failed!");
        return HDF_ERR_INVALID_PARAM;
    }
    for (auto it : dumpMap) {
        std::string dump = "compName = ";
        componentService = reinterpret_cast<CodecComponentService *>(it.second.GetRefPtr());
        dump.append(componentService->GetComponentCompName())
            .append(", compId = ")
            .append(std::to_string(it.first))
            .append(", state = ");
        componentService->GetComponentNode(dumpNode);
        dumpNode->GetState(state);
        dump.append(std::to_string(state));
        GetInstance().GetBuffCount();
        dump.append(", portIndex = ")
            .append(std::to_string(portIndex_i))
            .append(", BufferCount = ")
            .append(std::to_string(BuffCount_i))
            .append(", portIndex = ")
            .append(std::to_string(portIndex_j))
            .append(", BufferCount = ")
            .append(std::to_string(BuffCount_j))
            .append("\n");
        if (!HdfSbufWriteString(reply, dump.c_str())) {
            CODEC_LOGE("dump write Fail!");
            return HDF_ERR_INVALID_PARAM;
        }
        if (!HdfSbufWriteString(reply, "------------------------------------------------------------------------ \n")) {
            CODEC_LOGE("Split symbol write Fail!");
            return HDF_ERR_INVALID_PARAM;
        }
        BuffCount_i = 0;
        BuffCount_j = 0;
        componentService = nullptr;
    }
    return HDF_SUCCESS;
}

void CodecDfxService::SetComponentManager(sptr<CodecComponentManagerService> manager)
{
    managerService_ = manager;
}

CodecDfxService& CodecDfxService::GetInstance()
{
    return dfxInstance_;
}

int32_t CodecDfxService::DevCodecHostDump(struct HdfSBuf *data, struct HdfSBuf *reply)
{
    uint32_t argv = 0;
    (void)HdfSbufReadUint32(data, &argv);
    if (argv != ARGV_FLAG) {
        if (!HdfSbufWriteString(reply, "please enter -h for help! \n")) {
            CODEC_LOGE("help write Fail!");
            return HDF_ERR_INVALID_PARAM;
        }
        return HDF_SUCCESS;
    }

    const char *para = HdfSbufReadString(data);
    if (strcmp(para, "-h") == EOK) {
        if (!HdfSbufWriteString(reply, "-h: codec dump help! \n")) {
            CODEC_LOGE("-h write Fail!");
            return HDF_ERR_INVALID_PARAM;
        }
        if (!HdfSbufWriteString(reply, "-l: dump codec components info list! \n")) {
            CODEC_LOGE("-l write Fail!");
            return HDF_ERR_INVALID_PARAM;
        }
        return HDF_SUCCESS;
    } else if (strcmp(para, "-l") == EOK) {
        GetInstance().GetCodecComponentListInfo(reply);
    } else {
        HdfSbufWriteString(reply, "unknow param, please enter -h for help! \n");
    }
    return HDF_SUCCESS;
}
}  // namespace V1_0
}  // namespace Codec
}  // namespace HDI
}  // namespace OHOS
