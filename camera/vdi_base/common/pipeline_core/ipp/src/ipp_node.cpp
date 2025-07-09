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
#include "camera_metadata_operator.h"
#include "metadata_controller.h"
#include "ipp_node.h"

namespace OHOS::Camera {
IppNode::IppNode(const std::string& name, const std::string& type, const std::string &cameraId)
    : NodeBase(name, type, cameraId)
{
}

IppNode::~IppNode()
{
}

RetCode IppNode::Init(const int32_t streamId)
{
    (void)streamId;
    // initialize algo plugin
    if (offlineMode_.load()) {
        return RC_OK;
    }
    algoPluginManager_ = std::make_shared<AlgoPluginManager>();
    if (algoPluginManager_ == nullptr) {
        CAMERA_LOGE("create AlgoPluginManager failed");
        return RC_ERROR;
    }
    RetCode ret = algoPluginManager_->LoadPlugin();
    if (ret != RC_OK) {
        CAMERA_LOGE("load plugin failed.");
        return RC_ERROR;
    }
    return RC_OK;
}

RetCode IppNode::Start(const int32_t streamId)
{
    NodeBase::Start(streamId);
    // start offline stream process thread
    if (offlineMode_.load()) {
        return RC_OK;
    }
    algoPlugin_ = algoPluginManager_->GetAlgoPlugin(IPP_ALGO_MODE_NORMAL);
    StartProcess();
    return RC_OK;
}

RetCode IppNode::Flush(const int32_t streamId)
{
    if (offlineMode_.load()) {
        return RC_OK;
    }

    if (algoPlugin_ == nullptr) {
        CAMERA_LOGW("IppNode algoPlugin_ is null");
        return RC_ERROR;
    } else {
        algoPlugin_->Flush();
        NodeBase::Flush(streamId);
    }
    return RC_OK;
}

RetCode IppNode::SetCallback()
{
    RetCode rc = GetDeviceController();
    if (rc == RC_ERROR) {
        CAMERA_LOGE("GetDeviceController failed.");
        return RC_ERROR;
    }
    MetadataController& metaDataController = MetadataController::GetInstance();
    metaDataController.AddNodeCallback([this](const std::shared_ptr<CameraMetadata>& metadata) {
        OnMetadataChanged(metadata);
    });
    return RC_OK;
}

void IppNode::OnMetadataChanged(const std::shared_ptr<CameraMetadata>& metadata)
{
    if (metadata == nullptr) {
        CAMERA_LOGE("meta is nullptr");
        return;
    }
    // device metadata changed callback
    PrintNodeMetaData(metadata);
}

void IppNode::PrintNodeMetaData(const std::shared_ptr<CameraMetadata>& metadata)
{
    common_metadata_header_t *data = metadata->get();
    if (data == nullptr) {
        CAMERA_LOGE("data is null");
        return;
    }
    PrintFocusMode(data);
    PrintFocusState(data);
    PrintExposureMode(data);
    PrintExposureTime(data);
    PrintExposureCompensation(data);
    PrintExposureState(data);
}

void IppNode::PrintFocusMode(const common_metadata_header_t *data)
{
    uint8_t focusMode;
    camera_metadata_item_t entry;
    int ret = FindCameraMetadataItem(data, OHOS_CAMERA_FOCUS_MODE_LOCKED, &entry);
    if (ret != 0) {
        CAMERA_LOGE("get OHOS_CAMERA_FOCUS_MODE_LOCKED error");
        return;
    }
    focusMode = *(entry.data.u8);
    CAMERA_LOGI("focusMode =%{public}d", focusMode);
}

void IppNode::PrintFocusState(const common_metadata_header_t *data)
{
    uint8_t focusState;
    camera_metadata_item_t entry;
    int ret = FindCameraMetadataItem(data, OHOS_CAMERA_FOCUS_STATE_UNFOCUSED, &entry);
    if (ret != 0) {
        CAMERA_LOGE("get OHOS_CAMERA_FOCUS_STATE_UNFOCUSED error");
        return;
    }
    focusState = *(entry.data.u8);
    CAMERA_LOGI("focusState =%{public}d", focusState);
}

void IppNode::PrintExposureMode(const common_metadata_header_t *data)
{
    uint8_t exposureMode;
    camera_metadata_item_t entry;
    int ret = FindCameraMetadataItem(data, OHOS_CONTROL_EXPOSURE_MODE, &entry);
    if (ret != 0) {
        CAMERA_LOGE("get OHOS_CONTROL_EXPOSURE_MODE error");
        return;
    }
    exposureMode = *(entry.data.u8);
    CAMERA_LOGI("exposureMode =%{public}d", exposureMode);
}

void IppNode::PrintExposureTime(const common_metadata_header_t *data)
{
    int64_t exposureTime;
    camera_metadata_item_t entry;
    int ret = FindCameraMetadataItem(data, OHOS_SENSOR_EXPOSURE_TIME, &entry);
    if (ret != 0) {
        CAMERA_LOGE("get OHOS_SENSOR_EXPOSURE_TIME error");
        return;
    }
    exposureTime = *(entry.data.i64);
    CAMERA_LOGI("exposureTime =%{public}lld", exposureTime);
}

void IppNode::PrintExposureCompensation(const common_metadata_header_t *data)
{
    int32_t exposureCompensation;
    camera_metadata_item_t entry;
    int ret = FindCameraMetadataItem(data, OHOS_CONTROL_AE_EXPOSURE_COMPENSATION, &entry);
    if (ret != 0) {
        CAMERA_LOGE("get OHOS_CONTROL_AE_EXPOSURE_COMPENSATION error");
        return;
    }
    exposureCompensation = *(entry.data.i32);
    CAMERA_LOGI("exposureCompensation =%{public}d", exposureCompensation);
}

void IppNode::PrintExposureState(const common_metadata_header_t *data)
{
    uint8_t exposureState;
    camera_metadata_item_t entry;
    int ret = FindCameraMetadataItem(data, OHOS_CAMERA_EXPOSURE_STATE_SCAN, &entry);
    if (ret != 0) {
        CAMERA_LOGE("get OHOS_CAMERA_EXPOSURE_STATE_SCAN error");
        return;
    }
    exposureState = *(entry.data.u8);
    CAMERA_LOGI("exposureState =%{public}d", exposureState);
}

RetCode IppNode::GetDeviceController()
{
    deviceManager_ = IDeviceManager::GetInstance();
    if (deviceManager_ == nullptr) {
        CAMERA_LOGE("get device manager failed.");
        return RC_ERROR;
    }
    CameraId cameraId = CAMERA_FIRST;
    sensorController_ = std::static_pointer_cast<IController>
        (deviceManager_->GetController(cameraId, DM_M_SENSOR, DM_C_SENSOR));
    if (sensorController_ == nullptr) {
        CAMERA_LOGE("get device controller failed");
        return RC_ERROR;
    }
    return RC_OK;
}

RetCode IppNode::Stop(const int32_t streamId)
{
    // stop offline stream process thread
    if (offlineMode_.load()) {
        return RC_OK;
    }
    algoPlugin_->Stop();

    StopProcess();
    NodeBase::Stop(streamId);
    return RC_OK;
}

RetCode IppNode::Config(const int32_t streamId, const CaptureMeta& meta)
{
    (void)streamId;
    (void)meta;
    // configure algo
    // NodeBase::Configure
    if (offlineMode_.load()) {
        return RC_OK;
    }

    return RC_OK;
}

RetCode IppNode::SendNodeMetaData(const std::shared_ptr<CameraMetadata> meta)
{
    if (meta == nullptr) {
        CAMERA_LOGE("meta is nullptr");
        return RC_ERROR;
    }
    common_metadata_header_t *data = meta->get();
    if (data == nullptr) {
        CAMERA_LOGE("data is nullptr");
        return RC_ERROR;
    }

    RetCode rc = SendExposureMetaData(data);
    if (rc == RC_ERROR) {
        CAMERA_LOGE("SendExposureMetaData fail");
    }
    rc = SendFocusMetaData(data);
    if (rc == RC_ERROR) {
        CAMERA_LOGE("SendFocusMetaData fail");
    }
    return rc;
}

RetCode IppNode::SendExposureMetaData(const common_metadata_header_t *data)
{
    camera_metadata_item_t entry;
    (void) data;

    int ret = FindCameraMetadataItem(data, OHOS_CONTROL_EXPOSURE_MODE, &entry);
    if (ret == 0) {
        uint8_t exposureMode = *(entry.data.u8);
        CAMERA_LOGI("Set  exposureMode [%{public}d]", exposureMode);
    }

    ret = FindCameraMetadataItem(data, OHOS_SENSOR_EXPOSURE_TIME, &entry);
    if (ret == 0) {
        int64_t exposureTime = *(entry.data.i64);
        CAMERA_LOGI("Set exposureTime [%{public}d]", exposureTime);
    }

    ret = FindCameraMetadataItem(data, OHOS_CONTROL_AE_EXPOSURE_COMPENSATION, &entry);
    if (ret == 0) {
        int32_t exposureCompensation = *(entry.data.i32);
        CAMERA_LOGI("Set exposureCompensation [%{public}d]", exposureCompensation);
    }

    return RC_OK;
}

RetCode IppNode::SendFocusMetaData(const common_metadata_header_t *data)
{
    camera_metadata_item_t entry;
    (void) data;

    int ret = FindCameraMetadataItem(data, OHOS_CONTROL_FOCUS_MODE, &entry);
    if (ret == 0) {
        uint8_t focusMode = *(entry.data.u8);
        CAMERA_LOGI("Set focusMode [%{public}d]", focusMode);
    }

    ret = FindCameraMetadataItem(data, OHOS_CONTROL_AF_REGIONS, &entry);
    if (ret == 0) {
        std::vector<int32_t> afRegions;
        for (uint32_t i = 0; i < entry.count; i++) {
            CAMERA_LOGI("Set afRegions [%{public}d]", *(entry.data.i32 + i));
            afRegions.push_back(*(entry.data.i32 + i));
        }
    }

    return RC_OK;
}

void IppNode::DeliverBuffer(std::shared_ptr<IBuffer>& buffer)
{
    std::vector<std::shared_ptr<IBuffer>> cache;
    cache.emplace_back(buffer);
    ReceiveCache(cache);
    return;
}

void IppNode::DeliverBuffers(std::vector<std::shared_ptr<IBuffer>>& buffers)
{
    std::vector<std::shared_ptr<IBuffer>> cache;
    for (auto it : buffers) {
        cache.emplace_back(it);
    }

    ReceiveCache(cache);
    return;
}

void IppNode::ProcessCache(std::vector<std::shared_ptr<IBuffer>>& buffers)
{
    // process buffers with algorithm
    std::shared_ptr<IBuffer> outBuffer = nullptr;
    RetCode ret = GetOutputBuffer(buffers, outBuffer);
    if (ret != RC_OK) {
        CAMERA_LOGE("fatal error, can't get output buffer, ipp will do nothing.");
        return;
    }
    std::shared_ptr<CameraMetadata> meta = nullptr;
    if (algoPlugin_ != nullptr) {
        CAMERA_LOGV("process buffers with algo, input buffer count = %{public}u.", buffers.size());
        algoPlugin_->Process(outBuffer, buffers, meta);
    }

    std::shared_ptr<IBuffer> algoProduct = nullptr;
    std::vector<std::shared_ptr<IBuffer>> recycleBuffers{};
    ClassifyOutputBuffer(outBuffer, buffers, algoProduct, recycleBuffers);

    DeliverAlgoProductBuffer(algoProduct);
    DeliverCache(recycleBuffers);
    CAMERA_LOGV("process algo completed.");
    return;
}

void IppNode::DeliverCache(std::vector<std::shared_ptr<IBuffer>>& buffers)
{
    OfflinePipeline::DeliverCacheCheck(buffers);
}

void IppNode::DeliverCancelCache(std::vector<std::shared_ptr<IBuffer>>& buffers)
{
    std::shared_ptr<IBuffer> outBuffer = nullptr;
    RetCode ret = GetOutputBuffer(buffers, outBuffer);
    if (ret != RC_OK) {
        CAMERA_LOGE("fatal error, can't return buffer.");
        return;
    }

    std::shared_ptr<IBuffer> algoProduct = nullptr;
    std::vector<std::shared_ptr<IBuffer>> recycleBuffers{};
    ClassifyOutputBuffer(outBuffer, buffers, algoProduct, recycleBuffers);
    if (algoProduct == nullptr) {
        return;
    }
    DeliverAlgoProductBuffer(algoProduct);
    DeliverCache(recycleBuffers);

    return;
}

RetCode IppNode::GetOutputBuffer(std::vector<std::shared_ptr<IBuffer>>& buffers, std::shared_ptr<IBuffer>& outBuffer)
{
    auto outPort = GetOutPortById(0);
    if (outPort == nullptr) {
        CAMERA_LOGE("fatal error, can't get out port.");
        return RC_ERROR;
    }

    PortFormat format {};
    outPort->GetFormat(format);
    auto id = format.bufferPoolId_;
    for (auto it : buffers) {
        if (id == it->GetPoolId()) {
            outBuffer = nullptr;
            return RC_OK;
        }
    }

    auto bufferManager = BufferManager::GetInstance();
    if (bufferManager == nullptr) {
        CAMERA_LOGE("fatal error, can't get buffer manager.");
        return RC_ERROR;
    }
    auto bufferPool = bufferManager->GetBufferPool(id);
    if (bufferPool == nullptr) {
        CAMERA_LOGE("fatal error, can't get buffer pool.");
        return RC_ERROR;
    }

    outBuffer = bufferPool->AcquireBuffer(-1);

    return RC_OK;
}

void IppNode::DeliverAlgoProductBuffer(std::shared_ptr<IBuffer>& result)
{
    if (offlineMode_.load()) {
        CAMERA_LOGV("deliver buffer to offline stream");
        DeliverOfflineBuffer(result);
    } else {
        return NodeBase::DeliverBuffer(result);
    }

    return;
}

void IppNode::ClassifyOutputBuffer(std::shared_ptr<IBuffer>& outBuffer,
                                   std::vector<std::shared_ptr<IBuffer>>& inBuffers,
                                   std::shared_ptr<IBuffer>& product,
                                   std::vector<std::shared_ptr<IBuffer>>& recycleBuffers)
{
    if (outBuffer != nullptr) {
        product = outBuffer;
        recycleBuffers = inBuffers;
        return;
    }
    auto outPort = GetOutPortById(0);
    if (outPort == nullptr) {
        CAMERA_LOGE("fatal error, can't get out port.");
        return;
    }

    PortFormat format {};
    outPort->GetFormat(format);
    auto id = format.bufferPoolId_;
    auto it = std::find_if(inBuffers.begin(), inBuffers.end(),
                           [&id](const std::shared_ptr<IBuffer>& buffer) { return buffer->GetPoolId() == id; });
    if (it == inBuffers.end()) {
        CAMERA_LOGE("fatal error, outBuffer should be null.");
        return;
    }
    product = *it;
    inBuffers.erase(it);
    recycleBuffers = inBuffers;
    product->SetCaptureId(inBuffers[0]->GetCaptureId());
    product->SetBufferStatus(inBuffers[0]->GetBufferStatus());
    return;
}
REGISTERNODE(IppNode, {"ipp"});
} // namespace OHOS::Camera
