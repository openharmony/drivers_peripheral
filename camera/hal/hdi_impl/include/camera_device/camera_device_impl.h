/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#ifndef CAMERA_DEVICE_CAMERA_DEVICE_IMPL_H
#define CAMERA_DEVICE_CAMERA_DEVICE_IMPL_H

#include "v1_0/icamera_device.h"
#include "v1_0/icamera_device_callback.h"
#include "camera.h"
#include "camera_metadata_info.h"
#include "stream_operator.h"
#include <mutex>

namespace OHOS::Camera {
using namespace OHOS::HDI::Camera::V1_0;
class IPipelineCore;
class CameraDeviceImpl : public ICameraDevice, public std::enable_shared_from_this<CameraDeviceImpl> {
public:
    CameraDeviceImpl(const std::string &cameraId,
        const std::shared_ptr<IPipelineCore> &pipelineCore);
    CameraDeviceImpl() = default;
    virtual ~CameraDeviceImpl() = default;
    CameraDeviceImpl(const CameraDeviceImpl& other) = delete;
    CameraDeviceImpl(CameraDeviceImpl &&other) = delete;
    CameraDeviceImpl& operator=(const CameraDeviceImpl &other) = delete;
    CameraDeviceImpl& operator=(CameraDeviceImpl &&other) = delete;

public:
    int32_t GetStreamOperator(const sptr<IStreamOperatorCallback>& callbackObj,
        sptr<IStreamOperator>& streamOperator) override;
    int32_t UpdateSettings(const std::vector<uint8_t>& settings) override;
    int32_t SetResultMode(ResultCallbackMode mode) override;
    int32_t GetEnabledResults(std::vector<int32_t>& results) override;
    int32_t EnableResult(const std::vector<int32_t>& results) override;
    int32_t DisableResult(const std::vector<int32_t>& results) override;
    int32_t Close() override;

    static std::shared_ptr<CameraDeviceImpl> CreateCameraDevice(const std::string &cameraId);
    std::shared_ptr<IPipelineCore> GetPipelineCore() const;
    CamRetCode SetCallback(const OHOS::sptr<ICameraDeviceCallback> &callback);
    ResultCallbackMode GetMetaResultMode() const;
    /* RC_OK: metadata changed；RC_ERROR: metadata unchanged； */
    RetCode GetMetadataResults(std::shared_ptr<CameraMetadata> &metadata);
    void ResultMetadata();
    void GetCameraId(std::string &cameraId) const;
    void SetStatus(bool isOpened);
    void OnRequestTimeout();
    void OnMetadataChanged(const std::shared_ptr<CameraMetadata> &metadata);
    void OnDevStatusErr();
    bool IsOpened() const;
private:
    RetCode GetEnabledFromCfg();
    bool CompareTagData(const camera_metadata_item_t &baseEntry,
        const camera_metadata_item_t &newEntry);
    RetCode UpdataMetadataResultsBase();
    uint64_t GetCurrentLocalTimeStamp();

private:
    bool isOpened_;
    std::string cameraId_;
    std::shared_ptr<IPipelineCore> pipelineCore_;
    OHOS::sptr<ICameraDeviceCallback> cameraDeciceCallback_;
    OHOS::sptr<IStreamOperatorCallback> spCameraDeciceCallback_;
    OHOS::sptr<StreamOperator> spStreamOperator_;
    ResultCallbackMode metaResultMode_;
    std::vector<MetaType> deviceMetaTypes_;
    std::mutex enabledRstMutex_;
    std::vector<MetaType> enabledResults_;
    std::shared_ptr<CameraMetadata> metadataResultsBase_;
    std::mutex metaRstMutex_;
    std::shared_ptr<CameraMetadata> metadataResults_;

    // to keep OHOS::sptr<IStreamOperator> alive
    OHOS::sptr<IStreamOperator> ismOperator_ = nullptr;
};
} // end namespace OHOS::Camera
#endif // CAMERA_DEVICE_CAMERA_DEVICE_IMPL_H
