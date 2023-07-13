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

#ifndef OHOS_VDI_CAMERA_V1_0_ISTREAMOPERATORVDI_H
#define OHOS_VDI_CAMERA_V1_0_ISTREAMOPERATORVDI_H

#include <stdint.h>
#include <vector>
#include <hdf_base.h>
#include <hdi_base.h>
#include "buffer_producer_sequenceable.h"
#include "v1_0/ioffline_stream_operator_vdi.h"
#include "v1_0/istream_operator_vdi_callback.h"
#include "v1_0/vdi_types.h"

namespace OHOS {
namespace VDI {
namespace Camera {
namespace V1_0 {
using namespace OHOS;
using namespace OHOS::HDI;
using namespace OHOS::HDI::Camera::V1_0;

class IStreamOperatorVdi : public HdiBase {
public:
    virtual ~IStreamOperatorVdi() = default;

    virtual int32_t IsStreamsSupported(VdiOperationMode mode, const std::vector<uint8_t> &modeSetting,
         const std::vector<VdiStreamInfo> &infos, VdiStreamSupportType &type) = 0;

    virtual int32_t CreateStreams(const std::vector<VdiStreamInfo> &streamInfos) = 0;

    virtual int32_t ReleaseStreams(const std::vector<int32_t> &streamIds) = 0;

    virtual int32_t CommitStreams(VdiOperationMode mode, const std::vector<uint8_t> &modeSetting) = 0;

    virtual int32_t GetStreamAttributes(std::vector<VdiStreamAttribute> &attributes) = 0;

    virtual int32_t AttachBufferQueue(int32_t streamId, const sptr<BufferProducerSequenceable> &bufferProducer) = 0;

    virtual int32_t DetachBufferQueue(int32_t streamId) = 0;

    virtual int32_t Capture(int32_t captureId, const VdiCaptureInfo &info, bool isStreaming) = 0;

    virtual int32_t CancelCapture(int32_t captureId) = 0;

    virtual int32_t ChangeToOfflineStream(const std::vector<int32_t> &streamIds,
         const sptr<IStreamOperatorVdiCallback> &callbackObj, sptr<IOfflineStreamOperatorVdi> &offlineOperator) = 0;
};
} // V1_0
} // Camera
} // VDI
} // OHOS

#endif // OHOS_VDI_CAMERA_V1_0_ISTREAMOPERATORVDI_H
