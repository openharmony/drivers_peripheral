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

#ifndef HOS_CAMERA_IPP_NODE_H
#define HOS_CAMERA_IPP_NODE_H

#include "node_base.h"
#include "camera.h"
#include "offline_pipeline.h"
#include "algo_plugin_manager.h"
#include "algo_plugin.h"

namespace OHOS::Camera {
class IppNode : public NodeBase, public OfflinePipeline {
public:
    IppNode(const std::string& name, const std::string& type);
    ~IppNode();
    RetCode Init(const int32_t streamId) override;
    RetCode Start(const int32_t streamId) override;
    RetCode Stop(const int32_t streamId) override;
    RetCode Flush(const int32_t streamId) override;
    RetCode SetCallback(const MetaDataCb cb) override;
    RetCode Config(const int32_t streamId, const CaptureMeta& meta) override;
    RetCode UpdateSettingsConfig(const CaptureMeta& meta) override;
    void DeliverBuffer(std::shared_ptr<IBuffer>& buffer) override;
    void DeliverBuffers(std::vector<std::shared_ptr<IBuffer>>& buffers) override;
    void ProcessCache(std::vector<std::shared_ptr<IBuffer>>& buffers) override;
    void DeliverCache(std::vector<std::shared_ptr<IBuffer>>& buffers) override;
    void DeliverCancelCache(std::vector<std::shared_ptr<IBuffer>>& buffers) override;

protected:
    RetCode GetOutputBuffer(std::vector<std::shared_ptr<IBuffer>>& buffers, std::shared_ptr<IBuffer>& outBuffer);
    void DeliverAlgoProductBuffer(std::shared_ptr<IBuffer>& result);
    void ClassifyOutputBuffer(std::shared_ptr<IBuffer>& outBuffer,
                              std::vector<std::shared_ptr<IBuffer>>& inBuffers,
                              std::shared_ptr<IBuffer>& product,
                              std::vector<std::shared_ptr<IBuffer>>& recycleBuffers);
    RetCode GetDeviceController();
    void OnMetadataChanged(const std::shared_ptr<CameraMetadata>& metadata);
    RetCode SendNodeMetaData(const std::shared_ptr<CameraMetadata> meta);
    RetCode SendExposureMetaData(const common_metadata_header_t *data);
    RetCode SendFocusMetaData(const common_metadata_header_t *data);
    void GetNodeMetaData(std::shared_ptr<CameraMetadata> meta);
    void GetFocusMode(std::shared_ptr<CameraMetadata> meta);
    void GetFocusState(std::shared_ptr<CameraMetadata> meta);
    void GetExposureMode(std::shared_ptr<CameraMetadata> meta);
    void GetExposureTime(std::shared_ptr<CameraMetadata> meta);
    void GetExposureCompensation(std::shared_ptr<CameraMetadata> meta);
    void GetExposureState(std::shared_ptr<CameraMetadata> meta);

protected:
    std::shared_ptr<AlgoPluginManager> algoPluginManager_ = nullptr;
    std::shared_ptr<AlgoPlugin> algoPlugin_ = nullptr;
    std::shared_ptr<IController> sensorController_ = nullptr;
    std::shared_ptr<IDeviceManager> deviceManager_ = nullptr;
    MetaDataCb metaDataCb_ = nullptr;
};
} // namespace OHOS::Camera

#endif
