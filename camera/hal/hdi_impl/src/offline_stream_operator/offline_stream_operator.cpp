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

#include "offline_stream_operator.h"
#include "hitrace.h"
#include "watchdog.h"

namespace OHOS::Camera {
OfflineStreamOperator::OfflineStreamOperator(OHOS::sptr<IStreamOperatorCallback>& callback)
{
    callback_ = callback;
    CAMERA_LOGV("ctor, instance = %p", this);
}

OfflineStreamOperator::~OfflineStreamOperator()
{
    CAMERA_LOGV("dtor, instance = %p", this);
    offlineStreamMap_.clear();
}

CamRetCode OfflineStreamOperator::CancelCapture(int captureId)
{
    WatchDog watchDog;
    watchDog.Init(WATCHDOG_TIMEOUT, nullptr, true);

    HiviewDFX::HiTraceId traceId = OHOS::HiviewDFX::HiTrace::Begin("offlineStreamOperator", HITRACE_FLAG_DEFAULT);
    std::shared_ptr<OfflineStream> stream = FindStreamByCaptureId(captureId);
    if (stream == nullptr) {
        CAMERA_LOGD("can't find stream by captureId %{public}d, buffer all returned.", captureId);
        return NO_ERROR;
    }
    RetCode ret = stream->CancelCapture(captureId);
    if (ret != RC_OK) {
        CAMERA_LOGE("cancel captureId %{public}d failed", captureId);
        return DEVICE_ERROR;
    }
    OHOS::HiviewDFX::HiTrace::End(traceId);

    return NO_ERROR;
}

CamRetCode OfflineStreamOperator::ReleaseStreams(const std::vector<int>& streamIds)
{
    WatchDog watchDog;
    watchDog.Init(WATCHDOG_TIMEOUT, nullptr, true);

    HiviewDFX::HiTraceId traceId = OHOS::HiviewDFX::HiTrace::Begin("offlineStreamOperator", HITRACE_FLAG_DEFAULT);
    for (auto it : streamIds) {
        RetCode ret = offlineStreamMap_[it]->Release();
        if (ret != RC_OK) {
            CAMERA_LOGE("release stream %{public}d failed", it);
        }

        {
            std::lock_guard<std::mutex> l(lock_);
            offlineStreamMap_.erase(it);
        }
    }
    OHOS::HiviewDFX::HiTrace::End(traceId);

    return NO_ERROR;
}

CamRetCode OfflineStreamOperator::Release()
{
    WatchDog watchDog;
    watchDog.Init(WATCHDOG_TIMEOUT, nullptr, true);

    HiviewDFX::HiTraceId traceId = OHOS::HiviewDFX::HiTrace::Begin("offlineStreamOperator", HITRACE_FLAG_DEFAULT);
    {
        std::lock_guard<std::mutex> l(lock_);
        for (auto it = offlineStreamMap_.begin(); it != offlineStreamMap_.end(); it++) {
            it->second->Release();
        }

        offlineStreamMap_.clear();
    }
    OHOS::HiviewDFX::HiTrace::End(traceId);

    return NO_ERROR;
}

RetCode OfflineStreamOperator::CreateOfflineStream(int32_t id, std::shared_ptr<OfflineStreamContext>& context)
{
    auto stream = std::make_shared<OfflineStream>(id, context, callback_);
    if (stream == nullptr) {
        CAMERA_LOGE("create offline stream %{public}d failed.", id);
        return RC_ERROR;
    }

    if (stream->Init() != RC_OK) {
        CAMERA_LOGE("initialize offline stream %{public}d failed.", id);
        return RC_ERROR;
    }

    {
        std::lock_guard<std::mutex> l(lock_);
        offlineStreamMap_[id] = stream;
    }
    return RC_OK;
}

std::shared_ptr<OfflineStream> OfflineStreamOperator::FindStreamByCaptureId(int32_t captureId)
{
    std::shared_ptr<OfflineStream> stream = nullptr;
    {
        std::lock_guard<std::mutex> l(lock_);
        for (auto it = offlineStreamMap_.begin(); it != offlineStreamMap_.end(); it++) {
            if (it->second->CheckCaptureIdExist(captureId)) {
                stream = it->second;
            }
        }
    }
    return stream;
}
} // end namespace OHOS::Camera