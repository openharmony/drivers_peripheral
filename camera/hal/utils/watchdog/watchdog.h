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

#ifndef HOS_CAMERA_WATCHDOG_H
#define HOS_CAMERA_WATCHDOG_H

#include <thread>
#include <mutex>
#include <condition_variable>
#include <memory>

namespace OHOS::Camera {
class WatchDog {
public:
    WatchDog();
    void Init(int ms, std::function<void()> executor, bool isKill = false);
    ~WatchDog();

private:
    void WaitForWakeUP();
    void KillProcess();

private:
    int timeMs_ = 0;
    std::function<void()> executor_ = nullptr;
    std::condition_variable cv_;
    std::mutex lock_;
    std::thread handleThread_;
    bool terminate_ = false;
    bool isKill_ = false;
};
} // namespace OHOS::Camera

#endif
