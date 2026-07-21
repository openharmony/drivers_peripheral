/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
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

#include <thread>
#include <unistd.h>
#include <sys/select.h>
#include <sys/syscall.h>
#include "off_find_log.h"
#include "off_find_hdi_constant.h"
#include "dli_watcher.h"

namespace OHOS {
namespace HDI {
namespace Nearlink {
namespace OffFind {
DliWatcher::DliWatcher()
{}

DliWatcher::~DliWatcher()
{
    Stop();
}

bool DliWatcher::AddFdToWatcher(int fd, DliDataCallback callback)
{
    std::lock_guard<std::mutex> lock(fdsMutex_);
    fds_[fd] = callback;
    ThreadWakeup();
    return true;
}

bool DliWatcher::RemoveFdToWatcher(int fd)
{
    std::lock_guard<std::mutex> lock(fdsMutex_);
    fds_.erase(fd);
    ThreadWakeup();
    return true;
}

bool DliWatcher::SetTimeout(std::chrono::milliseconds timeout, TimeoutCallback callback)
{
    std::chrono::seconds seconds = std::chrono::duration_cast<std::chrono::seconds>(timeout);
    std::lock_guard<std::mutex> lock(timeoutMutex_);
    timeoutTimer_.tv_sec = seconds.count();
    timeoutTimer_.tv_usec = (timeout - seconds).count();
    timeoutCallback_ = callback;
    ThreadWakeup();
    return true;
}

bool DliWatcher::Start()
{
    if (running_.exchange(true)) {
        return true;
    }

    {
        std::lock_guard<std::mutex> lock(wakeupPipeMutex_);
        if (pipe(wakeupPipe_) != 0) {
            HDF_LOGE("DliWatcher create pipe failed.");
            running_.exchange(false);
            return false;
        }
    }

    thread_ = std::thread(std::bind(&DliWatcher::WatcherThread, this));
    if (!thread_.joinable()) {
        HDF_LOGE("thread is not joinable.");
        running_.exchange(false);
        return false;
    }

    int policy = SLE_THREAD_POLICY;
    sched_param params = {.sched_priority = SLE_THREAD_PRIORITY};
    if (pthread_setschedparam(thread_.native_handle(), policy, &params) != 0) {
        HDF_LOGW("pthread_setschedparam failed tid[%lu] policy[%d]", thread_.native_handle(), policy);
    }

    return true;
}

bool DliWatcher::Stop()
{
    if (!running_.exchange(false)) {
        return true;
    }

    ThreadWakeup();
    thread_.join();

    {
        std::lock_guard<std::mutex> lock(wakeupPipeMutex_);
        close(wakeupPipe_[0]);
        close(wakeupPipe_[1]);
    }

    return true;
}

void DliWatcher::CheckFdReady(std::map<int, DliDataCallback>& fds, fd_set &readFds)
{
    std::lock_guard<std::mutex> lock(fdsMutex_);
    for (auto &&fd : fds_) {
        if (FD_ISSET(fd.first, &readFds)) {
            fd.second(fd.first);
        }
    }
}

void DliWatcher::WatcherThread()
{
    fd_set readFds;
    int nfds;
    timeval *timeout = nullptr;

    while (running_) {
        FD_ZERO(&readFds);
        {
            std::lock_guard<std::mutex> lock(wakeupPipeMutex_);
            FD_SET(wakeupPipe_[0], &readFds);
            nfds = wakeupPipe_[0];
        }
        {
            std::lock_guard<std::mutex> lock(fdsMutex_);
            for (auto &&fd : fds_) {
                FD_SET(fd.first, &readFds);
                nfds = std::max(fd.first, nfds);
            }
        }

        {
            std::lock_guard<std::mutex> lock(timeoutMutex_);
            if (timeoutTimer_.tv_sec == 0 && timeoutTimer_.tv_usec == 0) {
                timeout = nullptr;
            } else {
                timeout = &timeoutTimer_;
            }
        }

        int ret = select(nfds + 1, &readFds, nullptr, nullptr, timeout);
        if (ret < 0) {
            continue;
        } else if (ret == 0) {
            TimeoutCallback callback;
            {
                std::lock_guard<std::mutex> lock(timeoutMutex_);
                callback = timeoutCallback_;
            }
            if (callback) {
                callback();
            }
        } else {
            {
                std::lock_guard<std::mutex> lock(wakeupPipeMutex_);
                if (FD_ISSET(wakeupPipe_[0], &readFds)) {
                    uint8_t buff = 0;
                    TEMP_FAILURE_RETRY(read(wakeupPipe_[0], &buff, sizeof(buff)));
                }
            }
            CheckFdReady(fds_, readFds);
        }
    }
}

void DliWatcher::ThreadWakeup()
{
    std::lock_guard<std::mutex> lock(wakeupPipeMutex_);
    uint8_t buff = 0;
    TEMP_FAILURE_RETRY(write(wakeupPipe_[1], &buff, sizeof(buff)));
}
}  // namespace Dli
}  // namespace Nearlink
}  // namespace HDI
}  // namespace OHOS