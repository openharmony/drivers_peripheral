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

#include "input_interface_device_info.h"

#include <system_error>

#include <sys/inotify.h>
#include <dirent.h>
#include <fcntl.h>
#include <sys/epoll.h>
#include <unistd.h>
#include <linux/input.h>
#include "hdf_log.h"
#include "securec.h"
#include "input_type.h"
#include "input_event_operate.h"

namespace OHOS {
namespace Input {
constexpr int32_t WAIT_TIME_FOR_INPUT = 10;
constexpr int32_t MAX_RETRY_COUNT = 5;
constexpr int32_t MAX_EVENT_BUF_SIZE = 512;
constexpr int32_t MAX_EVENT_SIZE = 100;
constexpr int32_t EPOLL_WAIT_TIME = 5 * 1000;
constexpr int32_t LOG_BUFFER_LEN = 256;
constexpr int32_t IOCTL_BUFFER_LEN = 256;
const std::string INPUT_DEVICES_PATH = "/dev/input/";

auto SystemError()
{
    return std::error_code{errno, std::system_category()};
}

void HdfLogFunc(struct libinput* input, libinput_log_priority priority, const char* fmt, va_list args)
{
    if (input == nullptr || fmt == nullptr) {
        HDF_LOGE("hi log func failed");
        return;
    }
    char buffer[LOG_BUFFER_LEN] = {};
    if (vsnprintf_s(buffer, sizeof(buffer), sizeof(buffer) - 1, fmt, args) == -1) {
        HDF_LOGE("Call vsnprintf_s failed");
        va_end(args);
        return;
    }
    HDF_LOGE("PrintLog_Info:%{public}s", buffer);
    va_end(args);
}

constexpr static libinput_interface LIBINPUT_INTERFACE = {
    .open_restricted = [](const char *path, int32_t flags, void *user_data)->int32_t {
        if (path == nullptr) {
            HDF_LOGI("Input device path is nullptr");
            return -1;
        }
        char realPath[PATH_MAX] = {};
        if (realpath(path, realPath) == nullptr) {
            std::this_thread::sleep_for(std::chrono::milliseconds(WAIT_TIME_FOR_INPUT));
            HDF_LOGI("The error path is %{public}s", path);
            return -1;
        }
        int32_t fd;
        for (int32_t i = 0; i < MAX_RETRY_COUNT; i++) {
            fd = open(realPath, flags);
            if (fd >= 0) {
                break;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(WAIT_TIME_FOR_INPUT));
        }
        int32_t errNo = errno;
        HDF_LOGI("Libinput .open_restricted path:%{public}s,fd:%{public}d,errno:%{public}d", path, fd, errNo);
        return fd < 0 ? -1 : fd;
    },
    .close_restricted = [](int32_t fd, void *user_data)
    {
        HDF_LOGI("Libinput .close_restricted fd:%{public}d", fd);
        close(fd);
    },
};

RetStatus DeviceInfo::InitHotPlug()
{
    HDF_LOGI("Init hot plug");
    inotifyFd_ = inotify_init1(IN_CLOEXEC);
    if (inotifyFd_ < 0) {
        HDF_LOGE("Failed to initialize inotify. errno: %{public}d.", errno);
        return INPUT_FAILURE;
    }
    if (inotify_add_watch(inotifyFd_, INPUT_DEVICES_PATH.c_str(), IN_DELETE | IN_CREATE) < 0) {
        HDF_LOGE("Failed to add watch for input devices. errno: %{public}d.", errno);
        return INPUT_FAILURE;
    }
    return Scan();
}

RetStatus DeviceInfo::IsDeviceSupported(const std::string &path, bool &supported)
{
    HDF_LOGI("is device supported");
    int32_t fd = open(path.c_str(), O_RDWR);
    if (fd < 0) {
        HDF_LOGE("open file failed, errno: %{public}d", errno);
        return INPUT_FAILURE;
    }

    char buffer[IOCTL_BUFFER_LEN];
    (void)memset_s(buffer, sizeof(buffer), 0, sizeof(buffer));

    int32_t ret = ioctl(fd, EVIOCGNAME(sizeof(buffer) - 1), &buffer);
    close(fd);
    if (ret < 1) {
        HDF_LOGE("get device name failed error: %{public}d", errno);
        return INPUT_FAILURE;
    }
    for (const auto &each : supportedDevice) {
        if (std::string(buffer).find(each) != std::string::npos) {
            supported = true;
            return INPUT_SUCCESS;
        }
    }
    supported = false;
    return INPUT_SUCCESS;
}

RetStatus DeviceInfo::Scan()
{
    HDF_LOGI("scan");
    using namespace std::literals::string_literals;
    auto* dir = opendir(INPUT_DEVICES_PATH.c_str());
    if (dir == nullptr) {
        HDF_LOGE("Failed to open device input dir. errno: %{public}d.", errno);
        return INPUT_FAILURE;
    }
    dirent* entry = nullptr;
    while ((entry = readdir(dir)) != nullptr) {
        if (entry->d_name == "."s || entry->d_name == ".."s) {
            continue;
        }
        bool supported = false;
        std::string path = std::string{INPUT_DEVICES_PATH} + entry->d_name;
        auto ret = IsDeviceSupported(path, supported);
        if (ret != INPUT_SUCCESS) {
            continue;
        }
        if (supported) {
            OnDeviceAdded(path);
        }
    }
    closedir(dir);
    return INPUT_SUCCESS;
}

void DeviceInfo::OnHotPlugEvent()
{
    constexpr int32_t EVSIZE = static_cast<int32_t>(sizeof(inotify_event));
    if (inotifyFd_ < 0) {
        return;
    }
    std::byte event_buf[MAX_EVENT_BUF_SIZE];
    int32_t res = read(inotifyFd_, event_buf, sizeof(event_buf));
    if (res < EVSIZE) {
        auto err = SystemError();
        if (err != std::errc::resource_unavailable_try_again) {
            HDF_LOGE("Filed to read inotify event. Error: %{public}s.", err.message().c_str());
        }
        return;
    }
    inotify_event event;
    for (int32_t pos = 0; res > EVSIZE;) {
        std::copy_n(event_buf + pos, sizeof(event), reinterpret_cast<std::byte*>(&event));
        if (event.len != 0) {
            auto path = INPUT_DEVICES_PATH + std::string{reinterpret_cast<char*>(event_buf + pos + sizeof(event))};
            if (event.mask & IN_CREATE) {
                OnDeviceAdded(path);
            } else {
                OnDeviceRemoved(path);
            }
        }
        int32_t consumed = EVSIZE + event.len;
        pos += consumed;
        res -= consumed;
    }
}


RetStatus DeviceInfo::EpollCreate()
{
    HDF_LOGI("Epoll create");
    epollFd_ = epoll_create(MAX_EVENT_SIZE);
    if (epollFd_ < 0) {
        HDF_LOGE("epoll_create return %{public}d", epollFd_);
        return INPUT_FAILURE;
    }
    HDF_LOGI("epoll_create, epollFd_:%{public}d", epollFd_);
    return INPUT_SUCCESS;
}

RetStatus DeviceInfo::CreateLibinputContext()
{
    HDF_LOGI("Create libinput context");
    input_ = libinput_path_create_context(&LIBINPUT_INTERFACE, nullptr);
    if (input_ == nullptr) {
        HDF_LOGE("create libinput context failed");
        return INPUT_FAILURE;
    }
    libinput_log_set_handler(input_, &HdfLogFunc);
    libinputFd_ = libinput_get_fd(input_);
    if (libinputFd_ < 0) {
        libinput_unref(input_);
        libinputFd_ = -1;
        HDF_LOGE("The fd_ is less than 0");
        return INPUT_FAILURE;
    }
    return INPUT_SUCCESS;
}

RetStatus DeviceInfo::AddToEpoll(int32_t fd)
{
    HDF_LOGI("Add to epoll");
    struct epoll_event eventItem;
    (void)memset_s(&eventItem, sizeof(eventItem), 0, sizeof(eventItem));
    eventItem.events = EPOLLIN;
    eventItem.data.fd = fd;
    int32_t ret = epoll_ctl(epollFd_, EPOLL_CTL_ADD, fd, &eventItem);
    if (ret < 0) {
        HDF_LOGE("add fd to epoll failed, ret=%d, errno=%d", ret, errno);
        return INPUT_FAILURE;
    }
    return INPUT_SUCCESS;
}

RetStatus DeviceInfo::RemoveEpoll(int32_t fd)
{
    HDF_LOGI("remove from epoll");
    int32_t ret = epoll_ctl(epollFd_, EPOLL_CTL_DEL, fd, nullptr);
    if (ret < 0) {
        HDF_LOGE("remove fd from epoll failed, ret=%d, errno=%d", ret, errno);
        return INPUT_FAILURE;
    }
    return INPUT_SUCCESS;
}

void DeviceInfo::EpollWaitThread()
{
    HDF_LOGI("epoll wait thread begin");
    ProcessPendingEvents();
    while (threadState_ == ThreadState::RUNNING) {
        epoll_event ev[MAX_EVENT_SIZE] = {};
        int32_t count = epoll_wait(epollFd_, ev, MAX_EVENT_SIZE, EPOLL_WAIT_TIME);
        if (count < 0) {
            HDF_LOGE("epoll wait failed, count=%d, errno=%d", count, errno);
            continue;
        }
        for (int32_t i = 0; i < count && threadState_ == ThreadState::RUNNING; i++) {
            if (ev[i].data.fd == inotifyFd_) {
                OnHotPlugEvent();
                continue;
            }
            OnLibinputEvent();
        }
        if (threadState_ == ThreadState::STOP) {
            break;
        }
    }
    HDF_LOGI("epoll wait thread thread stop");
}

RetStatus DeviceInfo::Init()
{
    HDF_LOGI("init libinput");
    RetStatus ret = INPUT_FAILURE;
    do {
        ret = EpollCreate();
        if (ret != INPUT_SUCCESS) {
            break;
        }
        ret = CreateLibinputContext();
        if (ret != INPUT_SUCCESS) {
            break;
        }
        ret = InitHotPlug();
        if (ret != INPUT_SUCCESS) {
            break;
        }
        ret = AddToEpoll(inotifyFd_);
        if (ret != INPUT_SUCCESS) {
            break;
        }
        ret = AddToEpoll(libinputFd_);
        if (ret != INPUT_SUCCESS) {
            break;
        }
        threadState_ = ThreadState::RUNNING;
        t_ = std::thread(std::bind(&DeviceInfo::EpollWaitThread, this));

    }while (0);

    if (ret != INPUT_SUCCESS) {
        Stop();
        return ret;
    }
    return INPUT_SUCCESS;
}

void DeviceInfo::Stop()
{
    HDF_LOGI("stop thread and libinput");
    threadState_ = ThreadState::STOP;
    t_.join();
    HDF_LOGI("epoll wait thread stopped");
    if (libinputFd_ >= 0) {
        close(libinputFd_);
        libinputFd_ = INVALID_FD;
    }
    if (input_ != nullptr) {
        libinput_unref(input_);
        input_ = nullptr;
    }
    if (inotifyFd_ >= 0) {
        close(inotifyFd_);
        inotifyFd_ = INVALID_FD;
    }
    if (epollFd_ >= 0) {
        close(epollFd_);
        epollFd_ = INVALID_FD;
    }
}

void DeviceInfo::ProcessPendingEvents()
{
    OnLibinputEvent();
}

void DeviceInfo::OnLibinputEvent()
{
    if (libinput_dispatch(input_) != 0) {
        HDF_LOGE("Failed to dispatch libinput");
        return;
    }

    libinput_event *event = nullptr;
    int i = 0;
    (void)memset_s(eventInfo_, sizeof(eventInfo_), 0, sizeof(eventInfo_));
    while ((event = libinput_get_event(input_))) {
        auto ret = TransformEvent(eventInfo_[i], event);
        libinput_event_destroy(event);
        if (ret != INPUT_SUCCESS) {
            continue;
        }
        i++;
        if (i == MAX_REPORT_EVENT_SIZE) {
            ReportLibinputEvent(i);
            (void)memset_s(eventInfo_, sizeof(eventInfo_), 0, sizeof(eventInfo_));
            i = 0;
        }
    }
    if (i > 0) {
        ReportLibinputEvent(i);
    }
}

void DeviceInfo::ReportLibinputEvent(int eventNum)
{
    if (reporterSptr == nullptr) {
        HDF_LOGE("reporterSptr is nullptr");
        return;
    }
    (void)reporterSptr->ReportEvent(eventInfo_, eventNum);
}

void DeviceInfo::OnDeviceAdded(const std::string &path)
{
    HDF_LOGI("device added");
    std::lock_guard<std::mutex> guard(devicesMtx_);
    libinput_device* device = libinput_path_add_device(input_, path.c_str());
    if (device == nullptr) {
        HDF_LOGE("add device failed");
        return;
    }
    devices_[path] = libinput_device_ref(device);
    // Libinput doesn't signal device adding event in path mode. Process manually.
    OnLibinputEvent();
}

void DeviceInfo::OnDeviceRemoved(const std::string &path)
{
    HDF_LOGI("device removed");
    std::lock_guard<std::mutex> guard(devicesMtx_);
    auto pos = devices_.find(path);
    if (pos != devices_.end()) {
        libinput_path_remove_device(pos->second);
        libinput_device_unref(pos->second);
        devices_.erase(pos);
        // Libinput doesn't signal device removing event in path mode. Process manually.
        OnLibinputEvent();
    }
}
} // namespace Input
} // namespace OHOS
