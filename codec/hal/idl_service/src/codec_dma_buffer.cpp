/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023. All rights reserved.
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

#include "codec_dma_buffer.h"
#include <hdf_base.h>
#include <securec.h>
#include <unistd.h>
#include <hdf_remote_service.h>
#include "codec_log_wrapper.h"
#include "v4_0/codec_types.h"
using namespace OHOS::HDI::Codec::V4_0;
namespace OHOS {
namespace Codec {
namespace Omx {

sptr<ICodecBuffer> CodecDMABuffer::UseBuffer(OMX_HANDLETYPE comp, uint32_t portIndex,
        OmxCodecBuffer &codecBuffer, OMX_BUFFERHEADERTYPE *&header)
{
    CHECK_AND_RETURN_RET_LOG(comp != nullptr, nullptr, "null component");
    CHECK_AND_RETURN_RET_LOG(codecBuffer.fd != nullptr, nullptr, "invalid dma fd");
    CHECK_AND_RETURN_RET_LOG(codecBuffer.allocLen > 0, nullptr, "invalid allocLen");
    CODEC_LOGI("port=%{public}u, use dmabuffer, fd=%{public}d", portIndex, codecBuffer.fd->Get());

    std::shared_ptr<UniqueFd> dmaFd = codecBuffer.fd;
    OMXBufferAppPrivateData priv{};
    int fd = codecBuffer.fd->Get();
    priv.fd = codecBuffer.fd->Get();
    priv.sizeOfParam = static_cast<uint32_t>(codecBuffer.alongParam.size());
    priv.param = static_cast<void *>(codecBuffer.alongParam.data());
    int32_t err = OMX_UseBuffer(comp, &header, portIndex, &priv, codecBuffer.allocLen,
        reinterpret_cast<OMX_U8 *>(&fd));
    if (err != OMX_ErrorNone) {
        CODEC_LOGE("OMX_UseBuffer ret = [%{public}x]", err);
        return nullptr;
    }
    codecBuffer.bufferhandle = nullptr;
    codecBuffer.fd.reset();
    codecBuffer.fenceFd.reset();
    return sptr<ICodecBuffer>(new CodecDMABuffer(
        InitInfo{comp, portIndex, codecBuffer, header}, dmaFd)
    );
}

sptr<ICodecBuffer> CodecDMABuffer::AllocateBuffer(OMX_HANDLETYPE comp, uint32_t portIndex,
        OmxCodecBuffer &codecBuffer, OMX_BUFFERHEADERTYPE *&header)
{
    CHECK_AND_RETURN_RET_LOG(comp != nullptr, nullptr, "null component");
    CHECK_AND_RETURN_RET_LOG(codecBuffer.allocLen > 0, nullptr, "invalid allocLen");

    OMXBufferAppPrivateData priv{};
    int32_t err = OMX_AllocateBuffer(comp, &header, portIndex, &priv, codecBuffer.allocLen);
    if (err != OMX_ErrorNone) {
        CODEC_LOGE("OMX_AllocateBuffer error, err = %{public}x", err);
        return nullptr;
    }
    CODEC_LOGI("port=%{public}u, allocate dmabuffer, fd=%{public}d", portIndex, priv.fd);
    std::shared_ptr<UniqueFd> dmaFd = UniqueFd::Create(priv.fd, false);
    codecBuffer.bufferhandle = nullptr;
    codecBuffer.fd = dmaFd;
    codecBuffer.fenceFd.reset();
    return sptr<ICodecBuffer>(new CodecDMABuffer(
        InitInfo{comp, portIndex, codecBuffer, header}, dmaFd)
    );
}

}  // namespace Omx
}  // namespace Codec
}  // namespace OHOS