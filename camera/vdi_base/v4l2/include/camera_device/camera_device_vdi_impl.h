/*
 * Copyright (c) 2021 - 2023 Huawei Device Co., Ltd.
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

#ifndef CAMERA_DEVICE_CAMERA_DEVICE_VDI_IMPL_H
#define CAMERA_DEVICE_CAMERA_DEVICE_VDI_IMPL_H

#include <mutex>
#include "v1_0/icamera_device_vdi.h"
#include "v1_0/icamera_device_vdi_callback.h"
#include "camera.h"
#include "camera_metadata_info.h"
#include "stream_operator_vdi_impl.h"

namespace OHOS::Camera {
using namespace OHOS::VDI::Camera::V1_0;
class IPipelineCore;

class CameraDeviceVdiImpl : public ICameraDeviceVdi, public std::enable_shared_from_this<CameraDeviceVdiImpl> {
public:
    CameraDeviceVdiImpl(const std::string &cameraId,
        const std::shared_ptr<IPipelineCore> &pipelineCore);
    CameraDeviceVdiImpl() = default;
    virtual ~CameraDeviceVdiImpl() = default;
    CameraDeviceVdiImpl(const CameraDeviceVdiImpl &other) = delete;
    CameraDeviceVdiImpl(CameraDeviceVdiImpl &&other) = delete;
    CameraDeviceVdiImpl &operator=(const CameraDeviceVdiImpl &other) = delete;
    CameraDeviceVdiImpl &operator=(CameraDeviceVdiImpl &&other) = delete;

public:
    int32_t GetStreamOperator(const sptr<IStreamOperatorVdiCallback> &callbackObj,
        sptr<IStreamOperatorVdi> &streamOperator) override;
    int32_t UpdateSettings(const std::vector<uint8_t> &settings) override;
    int32_t GetSettings(std::vector<uint8_t> &settings);
    int32_t SetResultMode(VdiResultCallbackMode mode) override;
    int32_t GetEnabledResults(std::vector<int32_t> &results) override;
    int32_t EnableResult(const std::vector<int32_t> &results) override;
    int32_t DisableResult(const std::vector<int32_t> &results) override;
    int32_t Close() override;

    static std::shared_ptr<CameraDeviceVdiImpl> CreateCameraDevice(const std::string &cameraId);
    std::shared_ptr<IPipelineCore> GetPipelineCore() const;
    VdiCamRetCode SetCallback(const OHOS::sptr<ICameraDeviceVdiCallback> &callback);
    VdiResultCallbackMode GetMetaResultMode() const;
    void GetCameraId(std::string &cameraId) const;
    void SetStatus(bool isOpened);
    void OnRequestTimeout();
    void OnMetadataChanged(const std::shared_ptr<CameraMetadata> &metadata);
    void OnDevStatusErr();
    bool IsOpened() const;
private:
    RetCode GetEnabledFromCfg();
    uint64_t GetCurrentLocalTimeStamp();
    void InitMetadataController();

private:
    bool isOpened_;
    std::string cameraId_;
    std::shared_ptr<IPipelineCore> pipelineCore_;
    OHOS::sptr<ICameraDeviceVdiCallback> cameraDeciceCallback_;
    OHOS::sptr<StreamOperatorVdiImpl> spStreamOperator_;
    VdiResultCallbackMode metaResultMode_;
    std::vector<MetaType> deviceMetaTypes_;
    std::mutex enabledRstMutex_;
    std::vector<MetaType> enabledResults_;
    std::shared_ptr<CameraMetadata> metadataResults_;

    // to keep OHOS::sptr<IStreamOperatorVdi> alive
    OHOS::sptr<IStreamOperatorVdi> ismOperator_ = nullptr;
};
} // end namespace OHOS::Camera
#endif // CAMERA_DEVICE_CAMERA_DEVICE_VDI_IMPL_H
