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

#include "stream_thread.h"
#include <iostream>
#include "camera.h"

namespace OHOS::Camera {
StreamThread::StreamThread()
    : thread_(nullptr),
      pauseFlag_(false),
      stopFlag_(false),
      state_(THREAD_STOP)
{
}

StreamThread::~StreamThread() {}

ThreadState StreamThread::GetState() const
{
    return state_;
}

RetCode StreamThread::Start()
{
    if (thread_ == nullptr) {
        thread_ = new (std::nothrow) std::thread(&StreamThread::Run, this);
        if (thread_ == nullptr) {
            CAMERA_LOGW("create stream thread failed.");
            return RC_ERROR;
        }
        pauseFlag_ = false;
        stopFlag_ = false;
        state_ = THREAD_RUNNING;
    }
    return RC_OK;
}

RetCode StreamThread::Stop()
{
    CAMERA_LOGD("hdi stream thread stop enter.");
    if (thread_ == nullptr) {
        CAMERA_LOGW("stream thread is null.");
        return RC_ERROR;
    }

    pauseFlag_ = false;
    stopFlag_ = true;
    condition_.notify_all();
    thread_->join();
    delete thread_;
    thread_ = nullptr;
    state_ = THREAD_STOP;
    CAMERA_LOGD("hdi stream thread stop success.");
    return RC_OK;
}

RetCode StreamThread::Pause()
{
    if (thread_ == nullptr) {
        CAMERA_LOGW("stream thread is null.");
        return RC_ERROR;
    }

    pauseFlag_ = true;
    state_ = THREAD_PAUSED;
    return RC_OK;
}

RetCode StreamThread::Resume()
{
    if (thread_ == nullptr) {
        CAMERA_LOGW("stream thread is null.");
        return RC_ERROR;
    }

    pauseFlag_ = false;
    condition_.notify_all();
    state_ = THREAD_RUNNING;
    return RC_OK;
}

void StreamThread::Run()
{
    CAMERA_LOGI("stream thread loop");
    prctl(PR_SET_NAME, "stream_thread");
    while (!stopFlag_) {
        Process();
        if (pauseFlag_) {
            std::unique_lock<std::mutex> locker(mutex_);
            while (pauseFlag_) {
                condition_.wait(locker);
            }
        }
    }
    pauseFlag_ = false;
    stopFlag_ = false;
}
}
