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

#ifndef OHOS_HDI_NEARLINK_DLI_WATCHER_H
#define OHOS_HDI_NEARLINK_DLI_WATCHER_H

#include <atomic>
#include <ctime>
#include <functional>
#include <map>
#include <mutex>
#include <sys/time.h>
#include <thread>

namespace OHOS {
namespace HDI {
namespace Nearlink {
namespace Dli {
class DliWatcher {
public:
    using DliDataCallback = std::function<void(int fd)>;
    using TimeoutCallback = std::function<void()>;

    DliWatcher();
    ~DliWatcher();

    bool AddFdToWatcher(int fd, DliDataCallback callback);
    bool RemoveFdToWatcher(int fd);
    bool SetTimeout(std::chrono::milliseconds timeout, TimeoutCallback callback);
    bool Start();
    bool Stop();

private:
    void CheckFdReady(std::map<int, DliDataCallback>& fds, fd_set &readFds);
    void InitReadFds(fd_set &readFds, int &nfds);
    void HandleTimeout();
    void HandleSelectEvent(fd_set &readFds);
    void WatcherThread();
    void ThreadWakeup();

private:
    std::atomic_bool running_ = {false};
    std::map<int, DliDataCallback> fds_;
    std::mutex fdsMutex_;
    std::mutex wakeupPipeMutex_;
    int wakeupPipe_[2] = {0};
    timeval timeoutTimer_ = {};
    TimeoutCallback timeoutCallback_;
    std::mutex timeoutMutex_;
    std::thread thread_;
};
}  // namespace Dli
}  // namespace Nearlink
}  // namespace HDI
}  // namespace OHOS
#endif /* OHOS_HDI_NEARLINK_DLI_WATCHER_H */