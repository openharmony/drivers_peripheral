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

#ifndef CODEC_HDI_DECODE_H
#define CODEC_HDI_DECODE_H
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
#include "codec_callback_type_service.h"
#include "codec_callback_type_stub.h"
#include "codec_component_manager.h"
#include "codec_component_type.h"
#include "codec_types.h"
#include "command_parse.h"

enum class PortIndex { PORT_INDEX_INPUT = 0, PORT_INDEX_OUTPUT = 1 };

class CodecHdiDecode {
    struct BufferInfo {
        std::shared_ptr<OmxCodecBuffer> omxBuffer;
        std::shared_ptr<OHOS::Ashmem> avSharedPtr;
        PortIndex portIndex;
        BufferHandle *bufferHandle;
        BufferInfo()
        {
            omxBuffer = nullptr;
            avSharedPtr = nullptr;
            portIndex = PortIndex::PORT_INDEX_INPUT;
            bufferHandle = nullptr;
        }
        ~BufferInfo()
        {
            omxBuffer = nullptr;
            if (avSharedPtr != nullptr) {
                avSharedPtr->UnmapAshmem();
                avSharedPtr->CloseAshmem();
                avSharedPtr = nullptr;
            }
            if (bufferHandle != nullptr && gralloc_ != nullptr) {
                gralloc_->FreeMem(*bufferHandle);
                bufferHandle = nullptr;
            }
            portIndex = PortIndex::PORT_INDEX_INPUT;
        }
        void setBufferHandle(BufferHandle *bufferHandle)
        {
            if (this->bufferHandle != nullptr) {
                if (gralloc_ != nullptr) {
                    gralloc_->FreeMem(*this->bufferHandle);
                }
            }
            this->bufferHandle = bufferHandle;
        }
    };

public:
    explicit CodecHdiDecode();
    ~CodecHdiDecode();
    bool Init(CommandOpt &opt);
    bool Configure();
    bool UseBuffers();
    void FreeBuffers();
    void Run();
    void Release();
    static int32_t OnEvent(struct CodecCallbackType *self, OMX_EVENTTYPE event, struct EventInfo *info);
    static int32_t OnEmptyBufferDone(struct CodecCallbackType *self, int64_t appData,
                                     const struct OmxCodecBuffer *buffer);
    static int32_t OnFillBufferDone(struct CodecCallbackType *self, int64_t appData,
                                    const struct OmxCodecBuffer *buffer);
    template <typename T>
    inline void InitParam(T &param)
    {
        memset_s(&param, sizeof(param), 0x0, sizeof(param));
        param.nSize = sizeof(param);
        param.nVersion.s.nVersionMajor = 1;  // mVersion.s.nVersionMajor;
    }
    template <typename T>
    inline void InitParamInOhos(T &param)
    {
        memset_s(&param, sizeof(param), 0x0, sizeof(param));
        param.size = sizeof(param);
        param.version.s.nVersionMajor = 1;  // mVersion.s.nVersionMajor;
    }
    void WaitForStatusChanged();
    void OnStatusChanged();
    bool ReadOnePacket(FILE *fp, char *buf, uint32_t &filledCount);

private:
    int32_t UseBufferOnPort(PortIndex portIndex);
    int32_t UseBufferOnPort(PortIndex portIndex, int bufferCount, int bufferSize);
    int32_t UseBufferHandle(int bufferCount, int bufferSize);
    int32_t OnEmptyBufferDone(const struct OmxCodecBuffer &buffer);
    int32_t OnFillBufferDone(const struct OmxCodecBuffer &buffer);
    int32_t CheckAndUseBufferHandle();
    int GetYuvSize();
    int32_t ConfigPortDefine();
    bool FillAllTheBuffer();
    int GetFreeBufferId();
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
    struct CodecComponentType *client_;
    struct CodecCallbackType *callback_;
    struct CodecComponentManager *omxMgr_;
    uint32_t componentId_;
    std::map<int, std::shared_ptr<BufferInfo>> omxBuffers_;  // key is buferid
    std::list<int> unUsedInBuffers_;
    std::list<int> unUsedOutBuffers_;
    std::mutex lockInputBuffers_;
    std::condition_variable statusCondition_;
    std::mutex statusLock_;
    bool exit_;
    codecMime codecMime_;
    bool useBufferHandle_;
    int count_;
    static constexpr uint32_t alignment_ = 16;
    static OHOS::HDI::Display::V1_0::IDisplayGralloc *gralloc_;
};
#endif /* CODEC_HDI_DECODE_H */