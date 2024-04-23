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

#ifndef CODEC_FUNCTION_UTIL_H
#define CODEC_FUNCTION_UTIL_H

#include <OMX_Component.h>
#include <OMX_Core.h>
#include <OMX_Video.h>
#include <OMX_VideoExt.h>
#include <list>
#include <map>
#include <securec.h>
#include "hdf_log.h"
#include "codec_omx_ext.h"
#include "v3_0/codec_callback_service.h"
#include "v3_0/icodec_component.h"
#include "v3_0/icodec_component_manager.h"
#include "v1_0/display_composer_type.h"
#include "v1_0/display_buffer_type.h"
#include "v1_0/include/idisplay_buffer.h"

constexpr int32_t WIDTH = 640;
constexpr uint32_t MAX_ROLE_INDEX = 256;
constexpr int FD_DEFAULT = -1;
constexpr int64_t APP_DATA = 3;
constexpr int32_t HEIGHT = 480;
constexpr int32_t BUFFER_SIZE = WIDTH * HEIGHT * 3;
constexpr int32_t FRAMERATE = 30 << 16;
constexpr uint32_t BUFFER_ID_ERROR = 65000;
constexpr int ERROE_FENCEFD = -1;
constexpr uint32_t WAIT_TIME = 1000;
constexpr uint32_t MAX_WAIT = 50;
constexpr uint32_t DENOMINATOR = 2;
constexpr uint32_t NUMERATOR = 3;
constexpr uint32_t ALIGNMENT = 16;

namespace OHOS {
namespace HDI {
namespace Codec {
namespace V3_0 {
enum class PortIndex { INDEX_INPUT = 0, INDEX_OUTPUT = 1 };
class FunctionUtil : public RefBase {
    struct BufferInfo {
        std::shared_ptr<OmxCodecBuffer> omxBuffer;
        std::shared_ptr<OHOS::Ashmem> sharedMem;
        BufferHandle *bufferHandle;
        BufferInfo()
        {
            omxBuffer = nullptr;
            sharedMem = nullptr;
            bufferHandle = nullptr;
        }
        ~BufferInfo()
        {
            omxBuffer = nullptr;
            if (sharedMem != nullptr) {
                sharedMem->UnmapAshmem();
                sharedMem->CloseAshmem();
                sharedMem = nullptr;
            }
            if (bufferHandle != nullptr && buffer_ != nullptr) {
                buffer_->FreeMem(*bufferHandle);
                bufferHandle = nullptr;
            }
        }
    };

public:
    explicit FunctionUtil(CodecVersionType version);

    ~FunctionUtil();

    template <typename T>
    void InitParam(T &param)
    {
        memset_s(&param, sizeof(param), 0x0, sizeof(param));
        param.nSize = sizeof(param);
        param.nVersion.nVersion = 1;
    }

    template <typename T>
    void InitExtParam(T &param)
    {
        memset_s(&param, sizeof(param), 0x0, sizeof(param));
        param.size = sizeof(param);
        param.version.nVersion = 1;
    }
    
    template <typename T>
    void ObjectToVector(T &param, std::vector<int8_t> &vec)
    {
        int8_t *paramPointer = reinterpret_cast<int8_t *>(&param);
        vec.insert(vec.end(), paramPointer, paramPointer + sizeof(param));
    }

    template <typename T>
    int32_t VectorToObject(std::vector<int8_t> &vec, T &param)
    {
        auto ret = memcpy_s(&param, sizeof(param), vec.data(), vec.size());
        if (ret != EOK) {
            HDF_LOGE("%{public}s error, memset_s ret [%{public}d", __func__, ret);
            return HDF_FAILURE;
        }
        vec.clear();
        return HDF_SUCCESS;
    }

    uint32_t AlignUp(uint32_t width);

    void InitOmxCodecBuffer(OmxCodecBuffer &buffer, CodecBufferType type);

    void InitCodecBufferWithAshMem(enum PortIndex port, int bufferSize, std::shared_ptr<OmxCodecBuffer> omxBuffer,
        std::shared_ptr<OHOS::Ashmem> sharedMem);

    bool InitBufferHandleParameter(sptr<ICodecComponent> component, OMX_PARAM_PORTDEFINITIONTYPE &param,
        uint32_t port, CodecBufferType bufferType);

    bool FillCodecBufferWithBufferHandle(std::shared_ptr<OmxCodecBuffer> omxBuffer);
    
    bool UseDynaBuffer(sptr<ICodecComponent> component, enum PortIndex port, int bufferCount, int bufferSize);

    bool UseHandleBuffer(sptr<ICodecComponent> component, enum PortIndex port, int bufferCount, int bufferSize);

    bool UseBufferOnPort(sptr<ICodecComponent> component, enum PortIndex port, int32_t bufferCount,
        int32_t bufferSize);

    bool AllocateBufferOnPort(sptr<ICodecComponent> component, enum PortIndex port, int32_t bufferCount,
        int32_t bufferSize);

    bool FreeBufferOnPort(sptr<ICodecComponent> component, enum PortIndex port);

    int32_t GetPortParameter(sptr<ICodecComponent> component, PortIndex index, OMX_PARAM_PORTDEFINITIONTYPE &param);

    bool FillAndEmptyAllBuffer(sptr<ICodecComponent> component, CodecBufferType type);

    bool WaitState(sptr<ICodecComponent> component, CodecStateType objState);

    bool PushAlongParam(OmxCodecBuffer &omxBuffer);

private:
    static OHOS::HDI::Display::Buffer::V1_0::IDisplayBuffer *buffer_;
    CodecVersionType version_;
    std::map<int32_t, std::shared_ptr<BufferInfo>> inputBuffers_;
    std::map<int32_t, std::shared_ptr<BufferInfo>> outputBuffers_;
};
} // V3_0
} // Codec
} // HDI
} // OHOS

#endif /* CODEC_FUNCTION_UTIL_H */
