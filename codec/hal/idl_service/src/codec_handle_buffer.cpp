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

#include "codec_handle_buffer.h"
#include <hdf_base.h>
#include <securec.h>
#include <unistd.h>
#include "codec_log_wrapper.h"
#include "v4_0/codec_types.h"
using namespace OHOS::HDI::Codec::V4_0;
namespace OHOS {
namespace Codec {
namespace Omx {

sptr<ICodecBuffer> CodecHandleBuffer::UseBuffer(OMX_HANDLETYPE comp, uint32_t portIndex,
    OmxCodecBuffer &codecBuffer, OMX_BUFFERHEADERTYPE *&header)
{
    CHECK_AND_RETURN_RET_LOG(comp != nullptr, nullptr, "null component");
    CHECK_AND_RETURN_RET_LOG(codecBuffer.bufferhandle != nullptr, nullptr, "null nativebuffer");
    BufferHandle *bufferHandle = codecBuffer.bufferhandle->GetBufferHandle();
    CHECK_AND_RETURN_RET_LOG(bufferHandle != nullptr, nullptr, "null bufferhandle");

    int32_t err = OMX_UseBuffer(comp, &header, portIndex, nullptr, codecBuffer.allocLen,
        reinterpret_cast<OMX_U8 *>(bufferHandle));
    if (err != OMX_ErrorNone) {
        CODEC_LOGE("OMX_UseBuffer ret = [%{public}x]", err);
        return nullptr;
    }
    sptr<HDI::Base::NativeBuffer> nativebuffer = codecBuffer.bufferhandle;
    codecBuffer.bufferhandle = nullptr;
    codecBuffer.fd.reset();
    codecBuffer.fenceFd.reset();
    return sptr<ICodecBuffer>(new CodecHandleBuffer(InitInfo{comp, portIndex, codecBuffer, header}, nativebuffer));
}

int32_t CodecHandleBuffer::FillThisBuffer(OmxCodecBuffer &codecBuffer)
{
    if (codecBuffer.fenceFd != nullptr) {
        auto ret = SyncWait(codecBuffer.fenceFd->Get(), TIME_WAIT_MS);
        if (ret != EOK) {
            CODEC_LOGE("SyncWait ret err [%{public}d]", ret);
        }
    }
    return ICodecBuffer::FillThisBuffer(codecBuffer);
}

int32_t CodecHandleBuffer::EmptyThisBuffer(OmxCodecBuffer &codecBuffer)
{
    CODEC_LOGE("bufferHandle is not support in EmptyThisBuffer");
    (void)codecBuffer;
    return OMX_ErrorNotImplemented;
}

}  // namespace Omx
}  // namespace Codec
}  // namespace OHOS