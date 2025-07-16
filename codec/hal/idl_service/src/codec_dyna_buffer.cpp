/*
 * Copyright (c) 2022-2023 Shenzhen Kaihong DID Co., Ltd..
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include "codec_dyna_buffer.h"
#include <buffer_handle_utils.h>
#include <hdf_base.h>
#include <securec.h>
#include <unistd.h>
#include "codec_log_wrapper.h"
#include "v4_0/codec_types.h"
using namespace OHOS::HDI::Codec::V4_0;
namespace OHOS {
namespace Codec {
namespace Omx {

sptr<ICodecBuffer> CodecDynaBuffer::UseBuffer(OMX_HANDLETYPE comp, uint32_t portIndex,
    OmxCodecBuffer &codecBuffer, OMX_BUFFERHEADERTYPE *&header)
{
    CHECK_AND_RETURN_RET_LOG(comp != nullptr, nullptr, "null component");

    codecBuffer.allocLen = sizeof(DynamicBuffer);
    std::shared_ptr<DynamicBuffer> dynamic = std::make_shared<DynamicBuffer>();
    int32_t err = OMX_UseBuffer(comp, &header, portIndex, nullptr, codecBuffer.allocLen,
        reinterpret_cast<OMX_U8 *>(dynamic.get()));
    if (err != OMX_ErrorNone) {
        CODEC_LOGE("OMX_UseBuffer ret = [%{public}x]", err);
        return nullptr;
    }

    codecBuffer.bufferhandle = nullptr;
    codecBuffer.fd.reset();
    codecBuffer.fenceFd.reset();
    return sptr<ICodecBuffer>(new CodecDynaBuffer(InitInfo{comp, portIndex, codecBuffer, header}, dynamic));
}

int32_t CodecDynaBuffer::FillThisBuffer(OmxCodecBuffer &codecBuffer)
{
    if (buffer_ == nullptr && codecBuffer.bufferhandle != nullptr) {
        BufferHandle* handle = codecBuffer.bufferhandle->GetBufferHandle();
        if (handle != nullptr) {
            buffer_ = codecBuffer.bufferhandle;
            dynaBuffer_->bufferHandle = handle;
        }
    }

    if (codecBuffer.fenceFd != nullptr) {
        auto ret = SyncWait(codecBuffer.fenceFd->Get(), TIME_WAIT_MS);
        if (ret != EOK) {
            CODEC_LOGW("SyncWait ret err");
        }
    }
    return ICodecBuffer::FillThisBuffer(codecBuffer);
}

int32_t CodecDynaBuffer::EmptyThisBuffer(OmxCodecBuffer &codecBuffer)
{
    if (codecBuffer.bufferhandle != nullptr) {
        BufferHandle* handle = codecBuffer.bufferhandle->GetBufferHandle();
        if (handle != nullptr) {
            buffer_ = codecBuffer.bufferhandle;
            dynaBuffer_->bufferHandle = handle;
            codecBuffer.filledLen = sizeof(DynamicBuffer);
        }
    }

    if (codecBuffer.fenceFd != nullptr) {
        auto ret = SyncWait(codecBuffer.fenceFd->Get(), TIME_WAIT_MS);
        if (ret != EOK) {
            CODEC_LOGW("SyncWait ret err");
        }
    }
    return ICodecBuffer::EmptyThisBuffer(codecBuffer);
}

}  // namespace Omx
}  // namespace Codec
}  // namespace OHOS