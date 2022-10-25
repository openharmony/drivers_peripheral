/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#ifndef CODEC_HDI_ADAPTER_DECODE_H
#define CODEC_HDI_ADAPTER_DECODE_H
#include <OMX_Component.h>
#include <OMX_Core.h>
#include <OMX_VideoExt.h>
#include <ashmem.h>
#include <buffer_handle.h>
#include <buffer_handle_utils.h>
#include <condition_variable>
#include <deque>
#include <list>
#include <map>
#include <memory>
#include <mutex>
#include <queue>
#include <thread>
#include <vector>
#include "codec_component_manager.h"
#include "codec_component_type.h"
#include "command_adapter_parse.h"

enum class PortIndex { PORT_INDEX_INPUT = 0, PORT_INDEX_OUTPUT = 1 };

class CodecHdiAdapterDecode {
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
            portIndex = PortIndex::PORT_INDEX_INPUT;
        }
    };

public:
    CodecHdiAdapterDecode();
    ~CodecHdiAdapterDecode();
    bool Init(CommandOpt &opt);
    bool Configure();
    bool UseBuffers();
    void FreeBuffers();
    void start();
    void Run();
    void Release();
    static int32_t OnEvent(struct CodecCallbackType *self, OMX_EVENTTYPE event, struct EventInfo *info);
    static int32_t OnEmptyBufferDone(
        struct CodecCallbackType *self, int64_t appData, const struct OmxCodecBuffer *buffer);
    static int32_t OnFillBufferDone(
        struct CodecCallbackType *self, int64_t appData, const struct OmxCodecBuffer *buffer);
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
    bool ReadOnePacket(FILE *fp, uint8_t *buf, uint32_t &filledCount);
    bool ReadOneFrameFromFile(FILE *fp, uint8_t *buf, uint32_t &filledCount);
    void DumpOutputToFile(FILE *fp, uint8_t *addr);

private:
    int32_t UseBufferOnPort(PortIndex portIndex);
    int32_t UseBufferOnPort(PortIndex portIndex, int bufferCount, int bufferSize);
    int32_t OnEmptyBufferDone(const struct OmxCodecBuffer &buffer);
    int32_t OnFillBufferDone(const struct OmxCodecBuffer &buffer);
    int32_t CheckAndUseBufferHandle();
    int GetYuvSize();
    int32_t ConfigPortDefine();
    int32_t ConfigMppPassthrough();
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
    uint32_t inputBufferSize_;
    uint32_t needSplit_;
    uint32_t srcFileSize_;
    uint32_t totalSrcSize_;
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
};
#endif /* CODEC_HDI_ADAPTER_DECODE_H */
