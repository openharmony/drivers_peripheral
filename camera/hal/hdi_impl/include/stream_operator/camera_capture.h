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

#ifndef HDI_CAMERA_CAPTURE_H
#define HDI_CAMERA_CAPTURE_H

#include <atomic>
#include "utils.h"
#include <map>

namespace OHOS::Camera {
class StreamBase;
class IStreamPipelineCore;
class CameraCapture {
public:
    CameraCapture(int captureId, const std::shared_ptr<CaptureInfo> &captureInfo, bool isStreaming,
        const std::weak_ptr<IStreamPipelineCore> &streamPipelineCore);
    virtual ~CameraCapture();
    CameraCapture(const CameraCapture &other) = delete;
    CameraCapture(CameraCapture &&other) = delete;
    CameraCapture& operator=(const CameraCapture &other) = delete;
    CameraCapture& operator=(CameraCapture &&other) = delete;

public:
    virtual void AddStream(const std::shared_ptr<StreamBase> &stream);
    virtual uint32_t DeleteStream(int streamId);
    virtual RetCode Start();
    virtual RetCode Cancel();
    virtual void RequestBuffer();
    virtual void ResultBuffer(int streamId, const std::shared_ptr<IBuffer> &buffer);
    virtual std::shared_ptr<CaptureInfo> GetCaptureInfo() const;
    virtual void SetCaptureCallback(const std::shared_ptr<CaptureCallback> &callback);

protected:
    int captureId_;
    std::shared_ptr<CaptureInfo> captureInfo_ = nullptr;
    std::vector<std::shared_ptr<StreamBase>> streams_;
    bool isStreaming_ = true;
    std::atomic<bool> isCancel_ = false;
    uint64_t frameCount_ = 0;
    std::weak_ptr<IStreamPipelineCore> streamPipelineCore_;
    std::shared_ptr<CaptureCallback> captureCallback_ = nullptr;
    // key：streamId；value：frameCount；
    std::map<int, uint64_t> streamFrameMap_;
    // key：streamId；value：stream error；
    std::map<int, StreamError> streamErrorMap_;

private:
    RetCode StreamResult(int streamId, const std::shared_ptr<IBuffer> &buffer);
    OperationType PolicyBufferOptType(int streamId, const std::shared_ptr<IBuffer> &buffer);
    void SaveResultCount(int streamId);
    void CaptureEnd();
    void StreamBufferError(int streamId, const std::shared_ptr<IBuffer> &buffer);
    void FrameShutter();
};
} // end namespace OHOS::Camera
#endif // HDI_CAMERA_CAPTURE_H
