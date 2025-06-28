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

#include "face_node.h"
#include <securec.h>
#include "camera_dump.h"
#include "camera_hal_hisysevent.h"

namespace OHOS::Camera {
FaceNode::FaceNode(const std::string &name, const std::string &type, const std::string &cameraId)
    : NodeBase(name, type, cameraId), metaDataSize_(0)
{
    CAMERA_LOGV("%{public}s enter, type(%{public}s)\n", name_.c_str(), type_.c_str());
}

FaceNode::~FaceNode()
{
    CAMERA_LOGI("~FaceNode Node exit.");
}

RetCode FaceNode::Start(const int32_t streamId)
{
    CAMERA_LOGI("FaceNode::Start streamId = %{public}d\n", streamId);
    CreateMetadataInfo();
    return RC_OK;
}

RetCode FaceNode::Stop(const int32_t streamId)
{
    CAMERA_LOGI("FaceNode::Stop streamId = %{public}d\n", streamId);
    std::unique_lock <std::mutex> lock(mLock_);
    metaDataSize_ = 0;
    return RC_OK;
}

RetCode FaceNode::Flush(const int32_t streamId)
{
    CAMERA_LOGI("FaceNode::Flush streamId = %{public}d\n", streamId);
    return RC_OK;
}

void FaceNode::DeliverBuffer(std::shared_ptr<IBuffer>& buffer)
{
    if (buffer == nullptr) {
        CAMERA_LOGE("FaceNode::DeliverBuffer frameSpec is null");
        return;
    }
    if (buffer->GetBufferStatus() != CAMERA_BUFFER_STATUS_OK) {
        CAMERA_LOGE("BufferStatus() != CAMERA_BUFFER_STATUS_OK");
        return NodeBase::DeliverBuffer(buffer);
    }

    CameraDumper& dumper = CameraDumper::GetInstance();
    dumper.DumpBuffer("FaceNode", ENABLE_FACE_NODE_CONVERTED, buffer);

    NodeBase::DeliverBuffer(buffer);
}

RetCode FaceNode::Config(const int32_t streamId, const CaptureMeta& meta)
{
    (void)meta;
    if (meta == nullptr || meta->get() == nullptr) {
        CAMERA_LOGE("FaceNode::Config meta is invalid");
        return RC_ERROR;
    }
    CAMERA_LOGD("FaceNode::Config streamId = %{public}d", streamId);
    return RC_OK;
}

RetCode FaceNode::Capture(const int32_t streamId, const int32_t captureId)
{
    CAMERA_LOGV("FaceNode::Capture streamId = %{public}d and captureId = %{public}d", streamId, captureId);
    return RC_OK;
}

RetCode FaceNode::CancelCapture(const int32_t streamId)
{
    CAMERA_LOGI("FaceNode::CancelCapture streamid = %{public}d", streamId);
    return RC_OK;
}

RetCode FaceNode::GetFaceDetectMetaData(std::shared_ptr<CameraMetadata> &metadata)
{
    GetCameraFaceDetectSwitch(metadata);
    GetCameraFaceRectangles(metadata);
    GetCameraFaceIds(metadata);
    return RC_OK;
}

RetCode FaceNode::GetCameraFaceDetectSwitch(std::shared_ptr<CameraMetadata> &metadata)
{
    uint8_t faceDetectSwitch = OHOS_CAMERA_FACE_DETECT_MODE_SIMPLE;
    metadata->addEntry(OHOS_STATISTICS_FACE_DETECT_SWITCH, &faceDetectSwitch, sizeof(uint8_t));
    return RC_OK;
}

RetCode FaceNode::GetCameraFaceRectangles(std::shared_ptr<CameraMetadata> &metadata)
{
    constexpr int32_t row = 3;
    constexpr int32_t col = 4;
    constexpr float rectOneX = 0.0; // dummy data: faceRectangles data
    constexpr float rectOneY = 0.0;
    constexpr float rectOneWidth = 0.2;
    constexpr float rectOneHeight = 0.3;

    constexpr float rectTwoX = 0.3; // dummy data: faceRectangles data
    constexpr float rectTwoY = 0.3;
    constexpr float rectTwoWidth = 0.2;
    constexpr float rectTwoHeight = 0.3;

    constexpr float rectThreeX = 0.6; // dummy data: faceRectangles data
    constexpr float rectThreeY = 0.6;
    constexpr float rectThreeWidth = 0.2;
    constexpr float rectThreeHeight = 0.3;

    float faceRectangles[row][col];
    faceRectangles[INDEX_0][INDEX_0] = rectOneX;
    faceRectangles[INDEX_0][INDEX_1] = rectOneY;
    faceRectangles[INDEX_0][INDEX_2] = rectOneWidth;
    faceRectangles[INDEX_0][INDEX_3] = rectOneHeight;

    faceRectangles[INDEX_1][INDEX_0] = rectTwoX;
    faceRectangles[INDEX_1][INDEX_1] = rectTwoY;
    faceRectangles[INDEX_1][INDEX_2] = rectTwoWidth;
    faceRectangles[INDEX_1][INDEX_3] = rectTwoHeight;

    faceRectangles[INDEX_2][INDEX_0] = rectThreeX;
    faceRectangles[INDEX_2][INDEX_1] = rectThreeY;
    faceRectangles[INDEX_2][INDEX_2] = rectThreeWidth;
    faceRectangles[INDEX_2][INDEX_3] = rectThreeHeight;
    metadata->addEntry(OHOS_STATISTICS_FACE_RECTANGLES, static_cast<void*>(&faceRectangles[0]),
        row * col);
    return RC_OK;
}

RetCode FaceNode::GetCameraFaceIds(std::shared_ptr<CameraMetadata> &metadata)
{
    std::vector<int32_t> vFaceIds;
    constexpr int32_t idZero = 0;
    constexpr int32_t idOne = 1;
    constexpr int32_t idTwo = 2;
    vFaceIds.push_back(idZero);
    vFaceIds.push_back(idOne);
    vFaceIds.push_back(idTwo);
    metadata->addEntry(OHOS_STATISTICS_FACE_IDS, vFaceIds.data(), vFaceIds.size());
    return RC_OK;
}

RetCode FaceNode::CopyMetadataBuffer(std::shared_ptr<CameraMetadata> &metadata,
    std::shared_ptr<IBuffer>& outPutBuffer, int32_t dataSize)
{
    int bufferSize = outPutBuffer->GetSize();
    uint32_t metadataSize = metadata->get()->size;
    CAMERA_LOGI("outPutBuffer.size = %{public}d dataSize = %{public}d and metadataSize = %{public}d",
        bufferSize, dataSize, metadataSize);
    int ret = 0;
    ret = memset_s(outPutBuffer->GetVirAddress(),  bufferSize, 0,  bufferSize);
    if (ret != RC_OK) {
        CAMERA_LOGE("memset_s failed");
        return RC_ERROR;
    }

    if (memcpy_s(outPutBuffer->GetVirAddress(), metadataSize, static_cast<void*>(metadata->get()),
        metadataSize) != 0) {
        CameraHalHisysevent::WriteFaultHisysEvent(CameraHalHisysevent::GetEventName(COPY_BUFFER_ERROR),
            CameraHalHisysevent::CreateMsg("streamId:%d CopyMetadataBuffer failed", outPutBuffer->GetStreamId()));
        CAMERA_LOGE("memcpy_s failed");
        return RC_ERROR;
    }
    outPutBuffer->SetEsFrameSize(metadataSize);
    return RC_OK;
}

RetCode FaceNode::CopyBuffer(uint8_t *sourceBuffer, std::shared_ptr<IBuffer>& outPutBuffer, int32_t dataSize)
{
    if (memcpy_s(outPutBuffer->GetVirAddress(), dataSize, sourceBuffer, dataSize) != 0) {
        CameraHalHisysevent::WriteFaultHisysEvent(CameraHalHisysevent::GetEventName(COPY_BUFFER_ERROR),
            CameraHalHisysevent::CreateMsg("streamId:%d CopyBuffer failed", outPutBuffer->GetStreamId()));
        CAMERA_LOGE("copy buffer memcpy_s failed");
        return RC_ERROR;
    }
    outPutBuffer->SetEsFrameSize(dataSize);
    return RC_OK;
}

RetCode FaceNode::CreateMetadataInfo()
{
    const int entryCapacity = 30; // 30:entry capacity
    const int dataCapacity = 2000; // 2000:data capacity
    std::unique_lock <std::mutex> lock(mLock_);
    metaData_ = std::make_shared<CameraMetadata>(entryCapacity, dataCapacity);
    RetCode result = GetFaceDetectMetaData(metaData_);
    if (result  != RC_OK) {
        CAMERA_LOGE("GetFaceDetectMetaData failed\n");
        return RC_ERROR;
    }
    return RC_OK;
}

REGISTERNODE(FaceNode, {"Face"})
} // namespace OHOS::Camera
