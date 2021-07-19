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

#ifndef STREAM_THREAD_H
#define STREAM_THREAD_H

#include <thread>
#include <mutex>
#include <atomic>
#include <condition_variable>
#include "camera.h"

namespace OHOS::Camera {
using ThreadState = enum _ThreadState {
    THREAD_STOP = 0,
    THREAD_RUNNING = 1,
    THREAD_PAUSED = 2,
};

class StreamThread {
public:
    StreamThread();
    ~StreamThread();

    ThreadState GetState() const;
    RetCode Start();
    RetCode Stop();
    RetCode Pause();
    RetCode Resume();

protected:
    virtual void Process() = 0;

private:
    void Run();

private:
    std::thread *thread_ = nullptr;
    std::mutex mutex_;
    std::condition_variable condition_;
    std::atomic_bool pauseFlag_ = {false};
    std::atomic_bool stopFlag_ = {false};
    ThreadState state_ = THREAD_STOP;
};
}
#endif // STREAM_THREAD_H