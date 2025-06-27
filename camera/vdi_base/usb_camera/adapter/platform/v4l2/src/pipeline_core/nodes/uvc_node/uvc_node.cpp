/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *     http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "uvc_node.h"
#include <unistd.h>
#include "metadata_controller.h"

constexpr int PIXEL_SPACE = 2;

namespace OHOS::Camera {
UvcNode::UvcNode(const std::string& name, const std::string& type, const std::string &cameraId)
    : NodeBase(name, type, cameraId), SourceNode(name, type, cameraId)
{
    CAMERA_LOGI("%{public}s enter, type(%{public}s)\n", name_.c_str(), type_.c_str());
    RetCode rc = RC_OK;
    constexpr int ITEM_CAPACITY_SIZE = 30;
    constexpr int DATA_CAPACITY_SIZE = 1000;
    deviceManager_ = IDeviceManager::GetInstance();
    if (deviceManager_ == nullptr) {
        CAMERA_LOGE("Get device manager failed.");
        return;
    }
    rc = GetDeviceController();
    if (rc == RC_ERROR) {
        CAMERA_LOGE("GetDeviceController failed.");
        return;
    }
    meta_ = std::make_shared<CameraMetadata>(ITEM_CAPACITY_SIZE, DATA_CAPACITY_SIZE);
}

UvcNode::~UvcNode()
{
    CAMERA_LOGI("~Uvc Node exit.");
}

struct MetadataTag {
    std::string cameraId1 = "lcam001";
    CameraId cameraId2 = CAMERA_FIRST;
};

CameraId UvcNode::ConvertCameraId(const std::string &cameraId)
{
    CameraId id = deviceManager_->HardwareToCameraId(cameraId);
    if (id == CAMERA_MAX) {
        CAMERA_LOGE("HardwareToCameraId error, cameraId = %{public}s", cameraId.c_str());
    }
    return id;
}

RetCode UvcNode::GetDeviceController()
{
    CameraId cameraId = ConvertCameraId(cameraId_);
    CAMERA_LOGI("GetDeviceController, cameraId = %{public}d, cameraId_ = %{public}s", cameraId, cameraId_.c_str());
    sensorController_ = std::static_pointer_cast<SensorController>
        (deviceManager_->GetController(cameraId, DM_M_SENSOR, DM_C_SENSOR));
    if (sensorController_ == nullptr) {
        CAMERA_LOGE("Get device controller failed");
        return RC_ERROR;
    }
    return RC_OK;
}

RetCode UvcNode::Init(const int32_t streamId)
{
    CAMERA_LOGD("UvcNode::Init streamId = %{public}d", streamId);
    return RC_OK;
}

RetCode UvcNode::Flush(const int32_t streamId)
{
    RetCode rc = RC_OK;

    if (sensorController_ != nullptr) {
        rc = sensorController_->Flush(streamId);
        CHECK_IF_NOT_EQUAL_RETURN_VALUE(rc, RC_OK, RC_ERROR);
    }
    rc = SourceNode::Flush(streamId);

    return rc;
}

RetCode UvcNode::Start(const int32_t streamId)
{
    RetCode rc = RC_OK;
    std::vector<std::shared_ptr<IPort>> outPorts = GetOutPorts();
    for (const auto& it : outPorts) {
        DeviceFormat format;
        format.fmtdesc.pixelformat = V4L2_PIX_FMT_YUYV;
        format.fmtdesc.width = wide_;
        format.fmtdesc.height = high_;
        int bufCnt = static_cast<int>(it->format_.bufferCount_);
        rc = sensorController_->Start(bufCnt, format);
        if (rc == RC_ERROR) {
            CAMERA_LOGE("Start failed.");
            return RC_ERROR;
        }
    }
    isAdjust_ = true;
    if (meta_ != nullptr) {
        sensorController_->ConfigFps(meta_);
    }
    rc = SourceNode::Start(streamId);
    return rc;
}

RetCode UvcNode::Stop(const int32_t streamId)
{
    RetCode rc = RC_OK;

    if (sensorController_ != nullptr) {
        rc = sensorController_->Stop();
        CHECK_IF_NOT_EQUAL_RETURN_VALUE(rc, RC_OK, RC_ERROR);
    }

    return SourceNode::Stop(streamId);
}

RetCode UvcNode::SetCallback()
{
    MetadataController &metaDataController = MetadataController::GetInstance();
    metaDataController.AddNodeCallback([this](const std::shared_ptr<CameraMetadata> &metadata) {
        OnMetadataChanged(metadata);
    });
    return RC_OK;
}

int32_t UvcNode::GetStreamId(const CaptureMeta &meta)
{
    common_metadata_header_t *data = meta->get();
    if (data == nullptr) {
        CAMERA_LOGE("Data is nullptr");
        return RC_ERROR;
    }
    camera_metadata_item_t entry;
    int32_t streamId = -1;
    int rc = FindCameraMetadataItem(data, OHOS_CAMERA_STREAM_ID, &entry);
    if (rc == 0) {
        streamId = *entry.data.i32;
    }
    return streamId;
}

void UvcNode::GetUpdateFps(const std::shared_ptr<CameraMetadata>& metadata)
{
    common_metadata_header_t *data = metadata->get();
    camera_metadata_item_t entry;
    int ret = FindCameraMetadataItem(data, OHOS_CONTROL_FPS_RANGES, &entry);
    if (ret == 0) {
        std::vector<int32_t> fpsRange;
        for (int i = 0; i < entry.count; i++) {
            fpsRange.push_back(*(entry.data.i32 + i));
        }
        meta_->addEntry(OHOS_CONTROL_FPS_RANGES, fpsRange.data(), fpsRange.size());
    }
}

void UvcNode::OnMetadataChanged(const std::shared_ptr<CameraMetadata>& metadata)
{
    if (metadata == nullptr) {
        CAMERA_LOGE("Meta is nullptr");
        return;
    }
    constexpr int32_t DEVICE_STREAM_ID = 0;
    if (sensorController_ != nullptr) {
        if (GetStreamId(metadata) == DEVICE_STREAM_ID) {
            sensorController_->Configure(metadata);
        }
    } else {
        CAMERA_LOGE("UvcNode sensorController_ is null");
    }
    GetUpdateFps(metadata);
}

void UvcNode::SetBufferCallback()
{
    sensorController_->SetNodeCallBack([&](std::shared_ptr<FrameSpec> frameSpec) {
        OnPackBuffer(frameSpec);
    });
    return;
}

static void SetImageAllBlack(uint8_t *buf, size_t bufferSize, uint32_t format)
{
    if (format == CAMERA_FORMAT_YUYV_422_PKG) {
        for (size_t i = 0; i + 1 < bufferSize; i += PIXEL_SPACE) {
            buf[i] = 0;
            buf[i + 1] = 0x80;
        }
    }
}

void UvcNode::DeliverBuffer(std::shared_ptr<IBuffer>& buffer)
{
    if (buffer == nullptr) {
        CAMERA_LOGE("UvcNode::DeliverBuffer frameSpec is null");
        return;
    }
    CAMERA_LOGI("UvcNode::DeliverBuffer Begin, streamId[%{public}d], index[%{public}d]",
        buffer->GetStreamId(), buffer->GetIndex());

    buffer->SetCurFormat(CAMERA_FORMAT_YUYV_422_PKG);
    buffer->SetCurWidth(wide_);
    buffer->SetCurHeight(high_);
    if (MetadataController::GetInstance().IsMute()) {
        SetImageAllBlack((uint8_t *)buffer->GetVirAddress(), buffer->GetSize(), CAMERA_FORMAT_YUYV_422_PKG);
    }

    SourceNode::DeliverBuffer(buffer);
    return;
}


RetCode UvcNode::ProvideBuffers(std::shared_ptr<FrameSpec> frameSpec)
{
    CAMERA_LOGI("UvcNode::ProvideBuffers enter. %{public}s", sensorController_->GetName().c_str());
    if (sensorController_->SendFrameBuffer(frameSpec) == RC_OK) {
        CAMERA_LOGD("Sendframebuffer success bufferpool id = %llu", frameSpec->bufferPoolId_);
        return RC_OK;
    }
    return RC_ERROR;
}
REGISTERNODE(UvcNode, {"uvc"})
} // namespace OHOS::Camera
