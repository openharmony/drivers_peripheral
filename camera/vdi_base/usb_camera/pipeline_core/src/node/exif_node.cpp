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

#include "exif_node.h"
#include <exif_utils.h>
#include <securec.h>
#include "camera_dump.h"

namespace OHOS::Camera {
ExifNode::ExifNode(const std::string &name, const std::string &type, const std::string &cameraId)
    : NodeBase(name, type, cameraId)
{
    CAMERA_LOGV("%{public}s enter, type(%{public}s)\n", name_.c_str(), type_.c_str());
}

ExifNode::~ExifNode()
{
    CAMERA_LOGI("~ExifNode Node exit.");
}

RetCode ExifNode::Start(const int32_t streamId)
{
    CAMERA_LOGI("ExifNode::Start streamId = %{public}d\n", streamId);
    return RC_OK;
}

RetCode ExifNode::Stop(const int32_t streamId)
{
    CAMERA_LOGI("ExifNode::Stop streamId = %{public}d\n", streamId);
    return RC_OK;
}

RetCode ExifNode::Flush(const int32_t streamId)
{
    CAMERA_LOGI("ExifNode::Flush streamId = %{public}d\n", streamId);
    return RC_OK;
}

void ExifNode::DeliverBuffer(std::shared_ptr<IBuffer> &buffer)
{
    if (buffer == nullptr) {
        CAMERA_LOGE("ExifNode::DeliverBuffer frameSpec is null");
        return;
    }
    if (buffer->GetBufferStatus() != CAMERA_BUFFER_STATUS_OK) {
        CAMERA_LOGE("BufferStatus() != CAMERA_BUFFER_STATUS_OK");
        return NodeBase::DeliverBuffer(buffer);
    }

    if (buffer->GetEncodeType() == ENCODE_TYPE_JPEG && gpsInfo_.size() > 0) {
        int outPutBufferSize = 0;
        exif_data exifInfo;
        exifInfo.latitude = gpsInfo_.at(LATITUDE_INDEX);
        exifInfo.longitude = gpsInfo_.at(LONGITUDE_INDEX);
        exifInfo.altitude = gpsInfo_.at(ALTITUDE_INDEX);
        EsFrameInfo info = buffer->GetEsFrameInfo();
        CAMERA_LOGI("%{public}s info.size = (%{public}d)\n", __FUNCTION__, info.size);
        if (info.size != -1) {
            exifInfo.frame_size = info.size;
            ExifUtils::AddCustomExifInfo(exifInfo, buffer->GetVirAddress(), outPutBufferSize);
            CAMERA_LOGI("%{public}s and outPutBufferSize = (%{public}d)\n", __FUNCTION__, outPutBufferSize);
            buffer->SetEsFrameSize(outPutBufferSize);
        }
    }

    CameraDumper& dumper = CameraDumper::GetInstance();
    dumper.DumpBuffer("ExifNode", ENABLE_EXIF_NODE_CONVERTED, buffer);

    NodeBase::DeliverBuffer(buffer);
}

RetCode ExifNode::Config(const int32_t streamId, const CaptureMeta &meta)
{
    if (meta == nullptr) {
        CAMERA_LOGW("%{public}s streamId= %{public}d", __FUNCTION__, streamId);
        return RC_OK;
    }
    if (SendMetadata(meta) == RC_ERROR) {
        CAMERA_LOGW("%{public}s no available caputre metadata", __FUNCTION__);
    }
    return RC_OK;
}

RetCode ExifNode::SendMetadata(std::shared_ptr<CameraMetadata> meta)
{
    common_metadata_header_t *data = meta->get();
    camera_metadata_item_t entry;
    uint8_t captureQuality = 0;
    int32_t captureOrientation = 0;
    uint8_t mirrorSwitch = 0;
    int ret = RC_OK;

    if (data == nullptr) {
        CAMERA_LOGE("%{public}s data is nullptr", __FUNCTION__);
        return RC_ERROR;
    }
    RetCode rc = SetGpsInfoMetadata(data);
    if (rc == RC_ERROR) {
        CAMERA_LOGE("%{public}s SetGpsInfoMetadata fail", __FUNCTION__);
        return RC_ERROR;
    }

    ret = FindCameraMetadataItem(data, OHOS_JPEG_QUALITY, &entry);
    if (ret != 0) {
        CAMERA_LOGE("%{public}s get OHOS_JPEG_QUALITY error and ret= %{public}d", __FUNCTION__, ret);
        return RC_ERROR;
    }
    captureQuality = *(entry.data.u8);
    ret = FindCameraMetadataItem(data, OHOS_JPEG_ORIENTATION, &entry);
    if (ret != 0) {
        CAMERA_LOGE("%{public}s get OHOS_JPEG_ORIENTATION error and ret= %{public}d", __FUNCTION__, ret);
        return RC_ERROR;
    }
    captureOrientation = *(entry.data.i32);
    ret = FindCameraMetadataItem(data, OHOS_CONTROL_CAPTURE_MIRROR, &entry);
    if (ret != 0) {
        CAMERA_LOGE("%{public}s get OHOS_CONTROL_CAPTURE_MIRROR error and ret= %{public}d", __FUNCTION__, ret);
        return RC_ERROR;
    }
    mirrorSwitch = *(entry.data.u8);
    CAMERA_LOGI("%{public}s captureQuality= %{public}d and captureOrientation= %{public}d and mirrorSwitch= %{public}d",
        __FUNCTION__, captureQuality, captureOrientation, mirrorSwitch);

    return rc;
}

RetCode ExifNode::SetGpsInfoMetadata(common_metadata_header_t *data)
{
    uint32_t count = 0;
    camera_metadata_item_t entry;
    int ret = FindCameraMetadataItem(data, OHOS_JPEG_GPS_COORDINATES, &entry);
    if (ret != 0) {
        return RC_ERROR;
    }
    constexpr uint32_t groupLen = 3;
    count = entry.count;
    CAMERA_LOGI("%{public}s  gps count %{public}d)\n", __FUNCTION__,  count);
    if (count != groupLen) {
        CAMERA_LOGE("%{public}s  gps data count error\n", __FUNCTION__);
        return RC_ERROR;
    }

    for (int i = 0; i < count; i++) {
        std::lock_guard<std::mutex> l(gpsMetaDatalock_);
        gpsInfo_.push_back(*(entry.data.d + i));
    }
    return RC_OK;
}

RetCode ExifNode::Capture(const int32_t streamId, const int32_t captureId)
{
    CAMERA_LOGV("ExifNode::Capture streamId = %{public}d and captureId = %{public}d", streamId, captureId);
    return RC_OK;
}

RetCode ExifNode::CancelCapture(const int32_t streamId)
{
    CAMERA_LOGI("ExifNode::CancelCapture streamid = %{public}d", streamId);

    return RC_OK;
}

REGISTERNODE(ExifNode, {"Exif"})
} // namespace OHOS::Camera
