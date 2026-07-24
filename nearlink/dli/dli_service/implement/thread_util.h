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

#ifndef SLE_THREAD_UTIL_H
#define SLE_THREAD_UTIL_H

#include <functional>
#ifdef RESOURCESCHEDULE_FFRT_ENABLE
#include "ffrt_inner.h"
#include <hdf_log.h>
#include "nearlink_hdf_log.h"
#else
#include <mutex>
#endif  // RESOURCESCHEDULE_FFRT_ENABLE

namespace OHOS {
namespace HDI {
namespace Nearlink {

using ThreadUtilFunc = std::function<void(void)>;

/**
 * @brief Post the task to the dli thread.
 * @param func The task to be executed.
 */
void DoInDliThread(const ThreadUtilFunc &func);

class ThreadUtil {
public:
    void PostTask(const ThreadUtilFunc &func);
    static ThreadUtil &GetInstance();
private:
    ThreadUtil();
    ~ThreadUtil();

    struct impl;
    std::unique_ptr<impl> pimpl;
};
}  // namespace Nearlink
}  // namespace HDI
}  // namespace OHOS

#endif  // SLE_THREAD_UTIL_H