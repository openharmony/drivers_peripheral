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

#include "thread_util.h"
#include <mutex>
#include "ffrt_inner.h"
#include <hdf_log.h>

namespace OHOS {
namespace HDI {
namespace Nearlink {

void DoInDliThread(const ThreadUtilFunc &func)
{
    ThreadUtil::GetInstance().PostTask(func);
}

struct ThreadUtil::impl {
    class TaskQueue {
    public:
        explicit TaskQueue(const char *name) : queue_(name, ffrt::queue_attr().qos(ffrt::qos_user_interactive)) {}
        ~TaskQueue() = default;

        void PostTask(const ThreadUtilFunc &func);
        int GetQueueId(void);

    private:
        ffrt::queue queue_;
    };

    impl();
    ~impl() = default;
    std::shared_ptr<TaskQueue> CreateTaskQueue();

    std::shared_ptr<TaskQueue> taskQueue;
};

ThreadUtil::impl::impl()
{}

ThreadUtil::ThreadUtil() : pimpl(std::make_unique<impl>())
{}

ThreadUtil::~ThreadUtil()
{}

void ThreadUtil::impl::TaskQueue::PostTask(const ThreadUtilFunc &func)
{
    queue_.submit(func);
}

int ThreadUtil::impl::TaskQueue::GetQueueId(void)
{
    int id = -1;
    auto handle = queue_.submit_h([&id]() {
        id = ffrt::get_queue_id();
    });
    queue_.wait(handle);
    return id;
}

void ThreadUtil::PostTask(const ThreadUtilFunc &func)
{
    std::lock_guard<ffrt::mutex> lock(taskQueueMutex_);
    std::shared_ptr<impl::TaskQueue> taskQueue = pimpl->taskQueue;
    if (taskQueue != nullptr) {
        taskQueue->PostTask(func);
        return;
    }
    // If the thread not found, create it.
    taskQueue = pimpl->CreateTaskQueue();
    // Execute the first task.
    if (taskQueue) {
        taskQueue->PostTask(func);
    }
}

std::shared_ptr<ThreadUtil::impl::TaskQueue> ThreadUtil::impl::CreateTaskQueue()
{
    std::string threadName = "sle_hci";
    auto taskQueue_ = std::make_shared<TaskQueue>(threadName.c_str());

    int queueId = taskQueue_->GetQueueId();
    HDF_LOGI("sle_ffrt_queue: queueId(%{public}d),  name(%{public}s)", queueId, threadName.c_str());

    taskQueue = taskQueue_;
    return taskQueue_;
}

ThreadUtil &ThreadUtil::GetInstance()
{
    static ThreadUtil instance;
    return instance;
}
}  // namespace Nearlink
}  // namepsace HDI
}  // namespace OHOS