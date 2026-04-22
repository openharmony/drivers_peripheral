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

#ifndef OHOS_HDI_SERIALS_V1_0_SERIAL_UEVENT_QUEUE_H
#define OHOS_HDI_SERIALS_V1_0_SERIAL_UEVENT_QUEUE_H

#include <stdint.h>
#include <map>
#include <string>
#include <functional>
#include <queue>
#include <mutex>
#include <thread>
#include <condition_variable>
#include <memory>

namespace OHOS {
namespace HDI {
namespace Serials {
namespace V1_0 {

struct SerialUeventInfo {
    std::string action;
    std::string devName;
    std::string subSystem;
    std::string devType;
    std::string devNum;
    std::string busNum;
};

using UeventCallback = std::function<void(const SerialUeventInfo& info)>;

class SerialUeventQueue {
public:
    SerialUeventQueue();
    ~SerialUeventQueue();

    int32_t Init();
    void Stop();
    void AddTask(const SerialUeventInfo& info);
    void SetCallback(const UeventCallback& callback);

private:
    void ProcessThreadMain();

    std::queue<SerialUeventInfo> queue_;
    std::mutex mutex_;
    std::condition_variable cv_;
    std::thread processThread_;
    UeventCallback callback_;
    bool running_ = false;
};

} // V1_0
} // Serials
} // HDI
} // OHOS

#endif // OHOS_HDI_SERIALS_V1_0_SERIAL_UEVENT_QUEUE_H