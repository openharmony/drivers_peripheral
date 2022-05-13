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
#include <buffer_handle_utils.h>
#include <condition_variable>
#include <deque>
#include <idisplay_gralloc.h>
#include <list>
#include <map>
#include <memory>
#include <mutex>
#include <queue>
#include <thread>
#include <vector>
#include "codec_callback_type_service.h"
#include "codec_callback_type_stub.h"
#include "codec_component_manager.h"
#include "codec_component_type.h"
#include "codec_types.h"
#include "command_parse.h"

enum class PortIndex { PORT_INDEX_INPUT = 0, PORT_INDEX_OUTPUT = 1 };

class CodecHdiEncode {
    struct BufferInfo {
        std::shared_ptr<struct OmxCodecBuffer> omxBuffer;
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
    ~CodecHdiEncode();

    bool Init(CommandOpt &opt);
    bool Configure();
    bool UseBuffers();
    int32_t UseBufferOnPort(PortIndex portIndex);
    void FreeBuffers();
    void Run();
    void Release();
    static int32_t OnEvent(struct CodecCallbackType *self, enum OMX_EVENTTYPE event, struct EventInfo *info);

    static int32_t OnEmptyBufferDone(struct CodecCallbackType *self, int8_t *appData, uint32_t appDataLen,
                                     const struct OmxCodecBuffer *buffer);
    static int32_t OnFillBufferDone(struct CodecCallbackType *self, int8_t *appData, uint32_t appDataLen,
                                    struct OmxCodecBuffer *buffer);
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
    void WaitForStatusChanged();
    void onStatusChanged();
    bool ReadOneFrame(FILE *fp, char *buf, uint32_t &filledCount);

private:
    int32_t OnEmptyBufferDone(const struct OmxCodecBuffer &buffer);
    int32_t OnFillBufferDone(struct OmxCodecBuffer &buffer);
    int32_t ConfigBitMode();
    int32_t UseBufferOnPort(PortIndex portIndex, int bufferCount, int bufferSize);
    bool FillAllTheBuffer();
    int GetFreeBufferId();
    int32_t ConfigPortDefine();
    int32_t CheckAndUseBufferHandle();
    int32_t UseDynaBuffer(int bufferCount, int bufferSize);
    bool FillCodecBuffer(std::shared_ptr<BufferInfo> bufferInfo, bool &endFlag);
    int32_t createBufferHandle();
    uint32_t inline align_up(uint32_t width)
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