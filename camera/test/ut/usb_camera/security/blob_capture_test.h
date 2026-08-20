/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#ifndef CAMERA_BLOB_CAPTURE_TEST_H
#define CAMERA_BLOB_CAPTURE_TEST_H

#include "test_camera_base.h"
#include <atomic>
#include <condition_variable>
#include <set>

/*
 * USB Camera BLOB capture UT test.
 * Uses PIXEL_FMT_BLOB for capture stream (passthrough path, Scale/Codec skipped),
 * while existing tests use PIXEL_FMT_RGBA_8888 (full encoding path).
 */

/*
 * StreamOperator callback with captureId tracking.
 * OnCaptureEnded records the captureId for later verification.
 */
class BlobStreamOperatorCallback : public IStreamOperatorCallback {
public:
    BlobStreamOperatorCallback() = default;
    virtual ~BlobStreamOperatorCallback() = default;

    int32_t OnCaptureStarted(int32_t captureId, const std::vector<int32_t>& streamIds) override
    {
        CAMERA_LOGI("BlobStreamOperatorCallback::OnCaptureStarted captureId=%{public}d", captureId);
        return RC_OK;
    }

    int32_t OnCaptureEnded(int32_t captureId, const std::vector<CaptureEndedInfo>& infos) override
    {
        CAMERA_LOGI("BlobStreamOperatorCallback::OnCaptureEnded captureId=%{public}d", captureId);
        std::lock_guard<std::mutex> lock(mtx_);
        endedCaptureIds_.insert(captureId);
        cv_.notify_all();
        return RC_OK;
    }

    int32_t OnCaptureError(int32_t captureId, const std::vector<CaptureErrorInfo>& infos) override
    {
        CAMERA_LOGI("BlobStreamOperatorCallback::OnCaptureError captureId=%{public}d", captureId);
        return RC_OK;
    }

    int32_t OnFrameShutter(int32_t captureId, const std::vector<int32_t>& streamIds, uint64_t timestamp) override
    {
        CAMERA_LOGI("BlobStreamOperatorCallback::OnFrameShutter captureId=%{public}d", captureId);
        return RC_OK;
    }

    bool WaitForCaptureEnded(int32_t captureId, int timeoutSec = 5)
    {
        std::unique_lock<std::mutex> lock(mtx_);
        return cv_.wait_for(lock, std::chrono::seconds(timeoutSec),
            [this, captureId]() { return endedCaptureIds_.count(captureId) > 0; });
    }

    bool HasCaptureEnded(int32_t captureId) const
    {
        std::lock_guard<std::mutex> lock(mtx_);
        return endedCaptureIds_.count(captureId) > 0;
    }

    void Reset()
    {
        std::lock_guard<std::mutex> lock(mtx_);
        endedCaptureIds_.clear();
    }

private:
    mutable std::mutex mtx_;
    std::condition_variable cv_;
    std::set<int32_t> endedCaptureIds_;
};

class CameraBlobCaptureTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp(void);
    void TearDown(void);
    std::shared_ptr<TestCameraBase> cameraBase_ = nullptr;
    OHOS::sptr<BlobStreamOperatorCallback> blobCallback_ = nullptr;

    static int cameraCount_;
    static std::vector<std::string> cameraIds_;

    std::atomic<int> frameCount_{0};
    std::mutex frameMtx_;
    std::condition_variable frameCv_;
    static constexpr int FRAME_WAIT_TIMEOUT_SEC = 5;

    void ResetFrameCount()
    {
        frameCount_ = 0;
    }

    void WaitForFrame(int expectedCount = 1, int timeoutSec = FRAME_WAIT_TIMEOUT_SEC)
    {
        std::unique_lock<std::mutex> lock(frameMtx_);
        frameCv_.wait_for(lock, std::chrono::seconds(timeoutSec),
            [this, expectedCount]() { return frameCount_ >= expectedCount; });
    }

    static bool IsValidJpeg(const unsigned char* data, uint32_t size)
    {
        if (data == nullptr || size < 4) {
            return false;
        }
        return (data[0] == 0xFF && data[1] == 0xD8);
    }
};
#endif /* CAMERA_BLOB_CAPTURE_TEST_H */
