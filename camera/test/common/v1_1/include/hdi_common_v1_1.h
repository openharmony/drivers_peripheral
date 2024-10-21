/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file expected in compliance with the License.
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

#ifndef HDI_COMMON_V1_1_H
#define HDI_COMMON_V1_1_H

#include "hdi_common.h"
#include "v1_1/types.h"
#include "v1_1/icamera_host.h"
#include "v1_1/icamera_device.h"
#include "v1_1/istream_operator.h"
#include "v1_1/camera_host_proxy.h"

namespace OHOS::Camera {
enum CameraIds {
    DEVICE_0, // rear camera
    DEVICE_1, // front camera
    DEVICE_2,
    DEVICE_3,
    DEVICE_4,
    DEVICE_5,
    DEVICE_6,
};
using namespace OHOS::HDI::Camera::V1_1;
class HdiCommonV1_1 : public OHOS::Camera::HdiCommon {
public:
    void Init();
    void Open(int cameraId);
    void GetCameraMetadata(int cameraId);
    void DefaultPreview(std::shared_ptr<StreamInfo_V1_1> &infos);
    void DefaultCapture(std::shared_ptr<StreamInfo_V1_1> &infos);
    void DefaultInfosPreview(std::shared_ptr<StreamInfo_V1_1> &infos);
    void DefaultInfosCapture(std::shared_ptr<StreamInfo_V1_1> &infos);
    void DefaultInfosAnalyze(std::shared_ptr<StreamInfo_V1_1> &infos);
    void DefaultInfosVideo(std::shared_ptr<StreamInfo_V1_1> &infos);
    void StartStream(std::vector<StreamIntent> intents);
    void StartStream(std::vector<StreamIntent> intents, OperationMode_V1_1 mode);
    void StartCapture(int streamId, int captureId, bool shutterCallback, bool isStreaming);
    void StopStream(std::vector<int>& captureIds, std::vector<int>& streamIds);
    OHOS::sptr<OHOS::HDI::Camera::V1_1::ICameraHost> serviceV1_1 = nullptr;
    OHOS::sptr<OHOS::HDI::Camera::V1_1::ICameraDevice> cameraDeviceV1_1 = nullptr;
    OHOS::sptr<OHOS::HDI::Camera::V1_1::IStreamOperator> streamOperator_V1_1 = nullptr;
    std::vector<StreamInfo_V1_1> streamInfos;
    std::vector<StreamInfo_V1_1> streamInfosV1_1;
    std::shared_ptr<PrelaunchConfig> prelaunchConfig = nullptr;
    std::shared_ptr<StreamInfo_V1_1> streamInfoV1_1 = nullptr;
    std::shared_ptr<StreamInfo_V1_1> streamInfo = nullptr;
    std::shared_ptr<StreamInfo_V1_1> streamInfoSnapshot = nullptr;
    std::shared_ptr<StreamInfo_V1_1> streamInfoCapture = nullptr;
    std::shared_ptr<StreamInfo_V1_1> streamInfoAnalyze = nullptr;
    std::shared_ptr<StreamInfo_V1_1> streamInfoPre = nullptr;
    std::shared_ptr<StreamInfo_V1_1> streamInfoVideo = nullptr;
    
    class StreamConsumer : public OHOS::Camera::HdiCommon::StreamConsumer {
    public:
        void GetTimeStamp(int64_t *g_timestamp, uint32_t lenght, int64_t timestamp, int32_t gotSize);
        OHOS::sptr<OHOS::IBufferProducer> CreateProducer(std::function<void(void*, uint32_t)> callback);
        OHOS::sptr<BufferProducerSequenceable> CreateProducerSeq(std::function<void(void*, uint32_t)> callback);
    public:
        static int64_t g_timestamp[2];
    };
};
}
#endif
