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

#ifndef OHOS_HDI_CAMERA_V1_0_ISTREAMOPERATORVDI_H
#define OHOS_HDI_CAMERA_V1_0_ISTREAMOPERATORVDI_H

#include <stdint.h>
#include <vector>
#include <hdf_base.h>
#include <hdi_base.h>
#include "buffer_producer_sequenceable.h"
#include "ioffline_stream_operator_vdi.h"
#include "v1_0/istream_operator_callback.h"
#include "v1_0/types.h"

#define ISTREAM_OPERATOR_VDI_MAJOR_VERSION 1
#define ISTREAM_OPERATOR_VDI_MINOR_VERSION 0

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

    virtual int32_t IsStreamsSupported(OperationMode mode, const std::vector<uint8_t> &modeSetting,
         const std::vector<StreamInfo> &infos, StreamSupportType &type) = 0;

    virtual int32_t CreateStreams(const std::vector<StreamInfo> &streamInfos) = 0;

    virtual int32_t ReleaseStreams(const std::vector<int32_t> &streamIds) = 0;

    virtual int32_t CommitStreams(OperationMode mode, const std::vector<uint8_t> &modeSetting) = 0;

    virtual int32_t GetStreamAttributes(std::vector<StreamAttribute> &attributes) = 0;

    virtual int32_t AttachBufferQueue(int32_t streamId, const sptr<BufferProducerSequenceable> &bufferProducer) = 0;

    virtual int32_t DetachBufferQueue(int32_t streamId) = 0;

    virtual int32_t Capture(int32_t captureId, const CaptureInfo &info, bool isStreaming) = 0;

    virtual int32_t CancelCapture(int32_t captureId) = 0;

    virtual int32_t ChangeToOfflineStream(const std::vector<int32_t> &streamIds,
         const sptr<IStreamOperatorCallback> &callbackObj, sptr<IOfflineStreamOperatorVdi> &offlineOperator) = 0;

    virtual int32_t GetVersion(uint32_t &majorVer, uint32_t &minorVer)
    {
        majorVer = ISTREAM_OPERATOR_VDI_MAJOR_VERSION;
        minorVer = ISTREAM_OPERATOR_VDI_MINOR_VERSION;
        return HDF_SUCCESS;
    }
};
} // V1_0
} // Camera
} // VDI
} // OHOS

#endif // OHOS_HDI_CAMERA_V1_0_ISTREAMOPERATORVDI_H
