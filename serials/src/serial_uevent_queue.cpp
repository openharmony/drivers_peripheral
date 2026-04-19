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

#include "serial_uevent_queue.h"
#include <poll.h>
#include <unistd.h>
#include "hdf_base.h"
#include "hdf_log.h"
#include "serial_consts.h"

#undef LOG_TAG
#define LOG_TAG "SERIAL_IMPL"
#undef LOG_DOMAIN
#define LOG_DOMAIN 0xD002519

namespace OHOS {
namespace HDI {
namespace Serials {
namespace V1_0 {

SerialUeventQueue::SerialUeventQueue() {}

SerialUeventQueue::~SerialUeventQueue()
{
    Stop();
}

int32_t SerialUeventQueue::Init()
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (running_) {
        HDF_LOGI("%{public}s: already running", __func__);
        return HDF_SUCCESS;
    }

    running_ = true;
    processThread_ = std::thread(&SerialUeventQueue::ProcessThreadMain, this);
    return HDF_SUCCESS;
}

void SerialUeventQueue::Stop()
{
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!running_) {
            return;
        }
        running_ = false;
    }
    cv_.notify_all();

    if (processThread_.joinable()) {
        processThread_.join();
    }
}

void SerialUeventQueue::AddTask(const SerialUeventInfo& info)
{
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!running_) {
            return;
        }
        queue_.push(info);
    }
    cv_.notify_one();
}

void SerialUeventQueue::SetCallback(const UeventCallback& callback)
{
    std::lock_guard<std::mutex> lock(mutex_);
    callback_ = callback;
}

void SerialUeventQueue::ProcessThreadMain()
{
    while (running_) {
        std::unique_lock<std::mutex> lock(mutex_);
        cv_.wait(lock, [this] { return !queue_.empty() || !running_; });

        if (!running_) {
            return;
        }

        while (!queue_.empty()) {
            SerialUeventInfo info = queue_.front();
            queue_.pop();
            lock.unlock();

            if (callback_) {
                callback_(info);
            }

            lock.lock();
        }
    }
}

} // V1_0
} // Serials
} // HDI
} // OHOS