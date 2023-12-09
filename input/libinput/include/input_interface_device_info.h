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
#ifndef INPUT_INTERFACE_DEVICE_INFO_H
#define INPUT_INTERFACE_DEVICE_INFO_H

#include <set>
#include <thread>
#include <unordered_map>
#include "libinput.h"
#include "input_type.h"
#include "input_interface_reporter.h"

namespace OHOS {
namespace Input {
constexpr int32_t INVALID_FD = -1;
constexpr int32_t MAX_REPORT_EVENT_SIZE = 100;
const std::string TOUCH_DEVICE_NAME = "input_mt_wrapper";

enum class ThreadState {STOP, RUNNING};

class DeviceInfo final {
public:
    DeviceInfo(std::shared_ptr<InputIfReporter> &reporter) : reporterSptr(reporter){};
    ~DeviceInfo() = default;
    DeviceInfo(const DeviceInfo &other) = delete;
    DeviceInfo(DeviceInfo &&other) = delete;
    DeviceInfo &operator=(const DeviceInfo &other) = delete;
    DeviceInfo &operator=(DeviceInfo &&other) = delete;

    RetStatus Init();
    void Stop();

private:
    RetStatus InitHotPlug();
    RetStatus EpollCreate();
    RetStatus CreateLibinputContext();
    RetStatus AddToEpoll(int32_t fd);
    RetStatus RemoveEpoll(int32_t fd);
    void EpollWaitThread();
    RetStatus Scan();
    void OnHotPlugEvent();
    void OnLibinputEvent();
    void ProcessPendingEvents();
    void ReportLibinputEvent(int eventNum);
    void OnDeviceAdded(const std::string &path);
    void OnDeviceRemoved(const std::string &path);
    RetStatus IsDeviceSupported(const std::string &path, bool &supported);

    int32_t epollFd_{INVALID_FD};
    int32_t libinputFd_{INVALID_FD};
    int32_t inotifyFd_{INVALID_FD};

    libinput *input_{nullptr};
    std::thread t_;
    ThreadState threadState_{ThreadState::STOP};
    std::shared_ptr<InputIfReporter> reporterSptr{nullptr};

    std::unordered_map<std::string, libinput_device*> devices_;
    std::mutex devicesMtx_;
    std::set<std::string> supportedDevice = {TOUCH_DEVICE_NAME};
    IfInputEvent eventInfo_[MAX_REPORT_EVENT_SIZE];
};
} // namespace Input
} // namespace OHOS
#endif // INPUT_INTERFACE_DEVICE_INFO_H