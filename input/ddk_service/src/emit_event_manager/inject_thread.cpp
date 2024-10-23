/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "inject_thread.h"
#include <sys/prctl.h>
#include "input_uhdf_log.h"

#define HDF_LOG_TAG inject_thread

namespace OHOS {
namespace ExternalDeviceManager {
InjectThread::InjectThread(std::shared_ptr<VirtualDevice> virtualDevice)
{
    virtualDevice_ = virtualDevice;
    threadRun_ = true;
}

InjectThread::~InjectThread()
{
    threadRun_ = false;
    conditionVariable_.notify_all();
    if (thread_.joinable()) {
        thread_.join();
    }
}

void InjectThread::Start()
{
    thread_ = std::thread([this] {this->RunThread(this);});
    pthread_setname_np(thread_.native_handle(), "emitEvent");
}

void InjectThread::RunThread(void *param)
{
    InjectThread *thread = reinterpret_cast<InjectThread *>(param);
    if (thread != nullptr) {
        thread->InjectFunc();
    } else {
        HDF_LOGE("%{public}s: thread is nullptr", __func__);
    }
}

void InjectThread::InjectFunc()
{
    prctl(PR_SET_NAME, "ExternalDeviceManager-inject");
    std::unique_lock<std::mutex> uniqueLock(mutex_);
    while (threadRun_) {
        conditionVariable_.wait(uniqueLock, [this] {
            return (injectQueue_.size() > 0 || !threadRun_);
        });
        for (auto &event : injectQueue_) {
            virtualDevice_->EmitEvent(event.type, event.code, event.value);
        }
        injectQueue_.clear();
    }
}

void InjectThread::WaitFunc(const std::vector<Hid_EmitItem> &items)
{
    std::lock_guard<std::mutex> lockGuard(mutex_);
    injectQueue_.insert(injectQueue_.begin(), items.begin(), items.end());
    conditionVariable_.notify_one();
}

void InjectThread::Stop()
{
    {
        std::lock_guard<std::mutex> lockGuard(mutex_);
        threadRun_ = false;
    }
    conditionVariable_.notify_all();
}
} // namespace ExternalDeviceManager
} // namespace OHOS