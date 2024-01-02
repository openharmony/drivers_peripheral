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

#ifndef INJECT_THREAD_H
#define INJECT_THREAD_H

#include <cstdint>
#include <memory>
#include <mutex>
#include <thread>
#include <vector>

#include "v1_0/hid_ddk_types.h"
#include "virtual_device.h"

namespace OHOS {
namespace ExternalDeviceManager {
using namespace OHOS::HDI::Input::Ddk::V1_0;
class InjectThread {
public:
    InjectThread(std::shared_ptr<VirtualDevice> virtualDevice);
    virtual ~InjectThread();
    void WaitFunc(const std::vector<Hid_EmitItem> &items);
    void Start();
    void Stop();

private:
    static void RunThread(void *param);
    void InjectFunc();

private:
    std::mutex mutex_;
    std::condition_variable conditionVariable_;
    bool threadRun_;
    std::vector<Hid_EmitItem> injectQueue_;
    std::thread thread_;
    std::shared_ptr<VirtualDevice> virtualDevice_;
};
} // namespace ExternalDeviceManager
} // namespace OHOS
#endif // INJECT_THREAD_H