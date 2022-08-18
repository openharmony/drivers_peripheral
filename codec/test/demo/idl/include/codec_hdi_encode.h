/*
 * Copyright 2022 Shenzhen Kaihong DID Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * 		http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef CODEC_HDI_ENCODE_H
#define CODEC_HDI_ENCODE_H

#include <OMX_Component.h>
#include <OMX_Core.h>
#include <OMX_VideoExt.h>
#include <ashmem.h>
#include <buffer_handle.h>
#include <condition_variable>
#include <idisplay_gralloc.h>
#include <list>
#include <map>
#include <memory>
#include <mutex>
#include <securec.h>
#include "codec_hdi_callback.h"
#include "command_parse.h"
#include "icodec_hdi_callback_base.h"
#include "v1_0/codec_types.h"
#include "v1_0/icodec_callback.h"
#include "v1_0/icodec_component.h"
#include "v1_0/icodec_component_manager.h"
using OHOS::HDI::Codec::V1_0::OmxCodecBuffer;
class CodecHdiEncode : public ICodecHdiCallBackBase,
                       public std::enable_shared_from_this<CodecHdiEncode> {
    enum class PortIndex { PORT_INDEX_INPUT = 0, PORT_INDEX_OUTPUT = 1 };
    struct BufferInfo {
        std::shared_ptr<OmxCodecBuffer> omxBuffer;
        std::shared_ptr<OHOS::Ashmem> avSharedPtr;
        int bufferHandleId;
        PortIndex portIndex;
        BufferInfo()
        {
            omxBuffer = nullptr;
            avSharedPtr = nullptr;
            portIndex = PortIndex::PORT_INDEX_INPUT;
            bufferHandleId = -1;
        }
        ~BufferInfo()
        {
            omxBuffer = nullptr;
            if (avSharedPtr) {
                avSharedPtr->UnmapAshmem();
                avSharedPtr->CloseAshmem();
                avSharedPtr = nullptr;
            }
            portIndex = PortIndex::PORT_INDEX_INPUT;
            bufferHandleId = -1;
        }
    };
    using BufferInfo = struct BufferInfo;

public:
    CodecHdiEncode();
    virtual ~CodecHdiEncode();

    bool Init(const CommandOpt &opt);
    bool Configure();
    bool UseBuffers();
    int32_t UseBufferOnPort(PortIndex portIndex);
    void FreeBuffers();
    void Run();
    void Release();
    template <typename T>
    inline void InitParam(T &param)
    {
        memset_s(&param, sizeof(param), 0x0, sizeof(param));
        param.nSize = sizeof(param);
        param.nVersion.s.nVersionMajor = 1;
    }
    template <typename T>
    inline void InitParamInOhos(T &param)
    {
        memset_s(&param, sizeof(param), 0x0, sizeof(param));
        param.size = sizeof(param);
        param.version.s.nVersionMajor = 1;  // mVersion.s.nVersionMajor;
    }
    template <typename T>
    void ObjectToVector(T &param, std::vector<int8_t> &vec)
    {
        vec.clear();
        int8_t *paramPointer = (int8_t *)&param;
        vec.insert(vec.end(), paramPointer, paramPointer + sizeof(param));
    }

    template <typename T>
    void VectorToObject(std::vector<int8_t> &vec, T &param)
    {
        (void)memcpy_s(&param, sizeof(param), vec.data(), vec.size());
        vec.clear();
    }
    void WaitForStatusChanged();
    void OnStatusChanged();
    bool ReadOneFrame(FILE *fp, char *buf, uint32_t &filledCount);
    int32_t OnEmptyBufferDone(const struct OmxCodecBuffer &buffer) override;
    int32_t OnFillBufferDone(const struct OmxCodecBuffer &buffer) override;
    int32_t EventHandler(OHOS::HDI::Codec::V1_0::OMX_EVENTTYPE event,
                         const OHOS::HDI::Codec::V1_0::EventInfo &info) override;

private:
    int32_t ConfigBitMode();
    int32_t UseBufferOnPort(PortIndex portIndex, int bufferCount, int bufferSize);
    bool FillAllTheBuffer();
    int GetFreeBufferId();
    int32_t ConfigPortDefine();
    int32_t CheckAndUseBufferHandle();
    int32_t UseDynaBuffer(int bufferCount, int bufferSize);
    bool FillCodecBuffer(std::shared_ptr<BufferInfo> bufferInfo, bool &endFlag);
    int32_t CreateBufferHandle();
    int32_t GetComponentName(std::string &compName);
    uint32_t inline AlignUp(uint32_t width)
    {
        return (((width) + alignment_ - 1) & (~(alignment_ - 1)));
    }

private:
    FILE *fpIn_;  // input file
    FILE *fpOut_;
    uint32_t width_;
    uint32_t height_;
    uint32_t stride_;
    OHOS::sptr<OHOS::HDI::Codec::V1_0::ICodecComponent> client_;
    OHOS::sptr<OHOS::HDI::Codec::V1_0::ICodecCallback> callback_;
    OHOS::sptr<OHOS::HDI::Codec::V1_0::ICodecComponentManager> omxMgr_;
    uint32_t componentId_;
    std::map<int, std::shared_ptr<BufferInfo>> omxBuffers_;  // key is bufferID
    std::list<int> unUsedInBuffers_;
    std::list<int> unUsedOutBuffers_;
    std::mutex lockInputBuffers_;
    std::condition_variable statusCondition_;
    std::mutex statusLock_;
    bool exit_;
    std::map<int, BufferHandle *> bufferHandles_;
    std::list<int> freeBufferHandles_;
    bool useBufferHandle_;
    static constexpr uint32_t alignment_ = 16;
    static OHOS::HDI::Display::V1_0::IDisplayGralloc *gralloc_;
};

#endif  // CODEC_HDI_ENCODE_H