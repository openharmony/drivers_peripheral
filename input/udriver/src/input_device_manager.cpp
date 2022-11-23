/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "input_device_manager.h"
#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <dirent.h>
#include <fcntl.h>
#include <fstream>
#include <functional>
#include <future>
#include <iostream>
#include <memory>
#include <sstream>
#include <sys/epoll.h>
#include <sys/inotify.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <vector>
#include "hdf_log.h"
#include "osal_mem.h"
#include "securec.h"

#define HDF_LOG_TAG InputDeviceHdiManager

namespace OHOS {
namespace Input {
using namespace std;
void InputDeviceManager::Init()
{
    inputDevList_.clear();
    reportEventPkgCallback_.clear();
    GetInputDeviceInfoList();
    std::thread t1(std::bind(&InputDeviceManager::WorkerThread, this));
    std::string wholeName1 = std::to_string(getpid()) + "_" + std::to_string(gettid());
    thread_ = std::move(t1);
    thread_.detach();
    for (auto &inputDev : inputDevList_) {
        dumpInfoList(inputDev.second);
    }
}

static void FreeEventPkgs(InputEventPackage **eventPkgs, size_t count)
{
    for (size_t i = 0; i < count; i++) {
        if (eventPkgs[i] != NULL) {
            free(eventPkgs[i]);
            eventPkgs[i] = nullptr;
        }
    }
    return;
}

// get the nodefile list
vector<string> InputDeviceManager::GetFiles(string path)
{
    vector<string> fileList;
    struct dirent *dEnt = nullptr;

    DIR *dir = opendir(path.c_str());
    if (dir == nullptr) {
        HDF_LOGE("%{public}s: no files", __func__);
        return fileList;
    }
    string sDot = ".";
    string sDotDot = "..";
    while ((dEnt = readdir(dir)) != nullptr) {
        if ((string(dEnt->d_name) != sDot) &&
            (string(dEnt->d_name) != sDotDot)) {
            if (dEnt->d_type != DT_DIR) {
                string d_name(dEnt->d_name);
                fileList.push_back(string(dEnt->d_name));
            }
        }
    }
    // sort the returned files
    sort(fileList.begin(), fileList.end());
    closedir(dir);
    return fileList;
}

// read action
void InputDeviceManager::DoRead(int32_t fd, struct input_event *event, size_t size)
{
    int32_t readLen = read(fd, event, sizeof(struct input_event) * size);

    if (readLen == 0 || (readLen < 0 && errno == ENODEV)) {
        return;
    } else if (readLen < 0) {
        if (errno != EAGAIN && errno != EINTR) {
            HDF_LOGE("%{public}s: could not get event (errno = %{public}d)", __func__, errno);
        }
    } else if ((readLen % sizeof(struct input_event)) != 0) {
        HDF_LOGE("%{public}s: could not get one event size %{public}lu  readLen size: %{public}d", __func__,
            sizeof(struct input_event), readLen);
    } else {
        size_t count = size_t(readLen) / sizeof(struct input_event);
        InputEventPackage **evtPkg = (InputEventPackage **)OsalMemAlloc(sizeof(InputEventPackage *) * count);
        if (evtPkg == nullptr) {
            HDF_LOGE("%{public}s: OsalMemAlloc failed, line: %{public}d", __func__, __LINE__);
            return;
        }
        for (size_t i = 0; i < count; i++) {
            struct input_event &iEvent = event[i];
            // device action events happened
            *(evtPkg + i) = (InputEventPackage *)OsalMemAlloc(sizeof(InputEventPackage));
            if (evtPkg[i] == nullptr) {
                HDF_LOGE("%{public}s: OsalMemAlloc failed, line: %{public}d", __func__, __LINE__);
                FreeEventPkgs(evtPkg, i);
                free(evtPkg);
                evtPkg = nullptr;
                return;
            }
            evtPkg[i]->type = iEvent.type;
            evtPkg[i]->code = iEvent.code;
            evtPkg[i]->value = iEvent.value;
            evtPkg[i]->timestamp = iEvent.time.tv_sec * MS_THOUSAND * MS_THOUSAND + iEvent.time.tv_usec;
        }
        for (auto &callbackFunc : reportEventPkgCallback_) {
            uint32_t index {0};
            auto ret = FindIndexFromFd(fd, &index);
            if (callbackFunc.second != nullptr && ret != INPUT_FAILURE) {
                callbackFunc.second->EventPkgCallback(const_cast<const InputEventPackage **>(evtPkg), count, index);
            }
        }
        for (size_t i = 0; i < count; i++) {
            OsalMemFree(evtPkg[i]);
            evtPkg[i] = nullptr;
        }
        OsalMemFree(evtPkg);
        evtPkg = nullptr;
    }
}

// open input device node
int32_t InputDeviceManager::OpenInputDevice(string devPath)
{
    char devRealPath[PATH_MAX + 1] = { '\0' };
    if (realpath(devPath.c_str(), devRealPath) == nullptr) {
        HDF_LOGE("%{public}s: The absolute path does not exist.", __func__);
        return INPUT_FAILURE;
    }

    int32_t nodeFd = open(devRealPath, O_RDWR | O_CLOEXEC | O_NONBLOCK);
    if (nodeFd < 0) {
        HDF_LOGE("%{public}s: could not open %{public}s, %{public}d %{public}s", __func__,
            devRealPath, errno, strerror(errno));
        return INPUT_FAILURE;
    }
    return nodeFd;
}

// close input device node
RetStatus InputDeviceManager::CloseInputDevice(string devPath)
{
    for (auto &inputDev : inputDevList_) {
        if (string(inputDev.second.devPathNode) == devPath) {
            int32_t fd = inputDev.second.fd;
            if (fd > 0) {
                RemoveEpoll(mEpollId_, fd);
                close(fd);
                fd = -1;
                inputDev.second.status = INPUT_DEVICE_STATUS_CLOSED;
                return INPUT_SUCCESS;
            }
        }
    }
    // device list remove this node
    return INPUT_FAILURE;
}

int32_t InputDeviceManager::GetInputDeviceInfo(int32_t fd, InputDeviceInfo *detailInfo)
{
    char buffer[DEVICE_INFO_SIZE] {};
    struct input_id inputId {};
    // get the abilitys.
    (void)ioctl(fd, EVIOCGBIT(EV_KEY, sizeof(detailInfo->abilitySet.keyCode)), &detailInfo->abilitySet.keyCode);
    (void)ioctl(fd, EVIOCGBIT(EV_REL, sizeof(detailInfo->abilitySet.relCode)), &detailInfo->abilitySet.relCode);
    (void)ioctl(fd, EVIOCGBIT(EV_ABS, sizeof(detailInfo->abilitySet.absCode)), &detailInfo->abilitySet.absCode);
    (void)ioctl(fd, EVIOCGBIT(EV_MSC, sizeof(detailInfo->abilitySet.miscCode)), &detailInfo->abilitySet.miscCode);
    (void)ioctl(fd, EVIOCGBIT(EV_SW, sizeof(detailInfo->abilitySet.switchCode)), &detailInfo->abilitySet.switchCode);
    (void)ioctl(fd, EVIOCGBIT(EV_LED, sizeof(detailInfo->abilitySet.ledType)), &detailInfo->abilitySet.ledType);
    (void)ioctl(fd, EVIOCGBIT(EV_SND, sizeof(detailInfo->abilitySet.soundCode)), &detailInfo->abilitySet.soundCode);
    (void)ioctl(fd, EVIOCGBIT(EV_FF, sizeof(detailInfo->abilitySet.forceCode)), &detailInfo->abilitySet.forceCode);
    // device name.
    if (ioctl(fd, EVIOCGNAME(sizeof(buffer) - 1), &buffer) < 1) {
        HDF_LOGE("%{public}s: get device name failed errormsg %{public}s", __func__, strerror(errno));
    } else {
        buffer[sizeof(buffer) - 1] = '\0';
        int32_t ret = strcpy_s(detailInfo->attrSet.devName, DEVICE_INFO_SIZE, buffer);
        if (ret) {
            HDF_LOGE("%{public}s: strcpy_s failed, ret %{public}d", __func__, ret);
        }
    }
    // device detailInfo.
    if (ioctl(fd, EVIOCGID, &inputId)) {
        HDF_LOGE("%{public}s: get device input id errormsg %{public}s", __func__, strerror(errno));
    }
    detailInfo->attrSet.id.busType = inputId.bustype;
    detailInfo->attrSet.id.product = inputId.product;
    detailInfo->attrSet.id.vendor = inputId.vendor;
    detailInfo->attrSet.id.version = inputId.version;
    // ABS Info
    for (uint32_t i = 0; i < ABS_CNT; i++) {
        if (detailInfo->abilitySet.absCode[i] > 0) {
            if (ioctl(fd, EVIOCGABS(i), &detailInfo->attrSet.axisInfo[i])) {
                HDF_LOGE("%{public}s: get axis info failed fd = %{public}d name = %{public}s errormsg = %{public}s",
                         __func__, fd, detailInfo->attrSet.devName, strerror(errno));
                continue;
            }
        }
    }
    return INPUT_SUCCESS;
}

void InputDeviceManager::GetInputDeviceInfoList(int32_t epollFd)
{
    inputDevList_.clear();
    std::vector<std::string> flist = GetFiles(devPath_);
    std::shared_ptr<InputDeviceInfo> detailInfo;
    InputDevListNode inputDevList {};
    uint32_t type {INDEV_TYPE_UNKNOWN};

    for (unsigned i = 0; i < flist.size(); i++) {
        string devPathNode = devPath_ + "/" + flist[i];
        std::string::size_type n = devPathNode.find("event");
        if (n != std::string::npos) {
            auto fd = OpenInputDevice(devPathNode);
            if (fd < 0) {
                HDF_LOGE("%{public}s: open node failed", __func__);
                continue;
            }
            detailInfo = std::make_shared<InputDeviceInfo>();
            (void)memset_s(detailInfo.get(), sizeof(InputDeviceInfo), 0, sizeof(InputDeviceInfo));
            (void)GetInputDeviceInfo(fd, detailInfo.get());
            auto sDevName = string(detailInfo->attrSet.devName);
            if (sDevName.find("input_mt_wrapper") != std::string::npos) {
                type = INDEV_TYPE_TOUCH;
            } else if ((sDevName.find("Keyboard") != std::string::npos) &&
                       (sDevName.find("Headset") == std::string::npos)) {
                type = INDEV_TYPE_KEYBOARD;
            } else if (sDevName.find("Mouse") != std::string::npos) {
                type = INDEV_TYPE_MOUSE;
            } else if ((sDevName.find("_gpio_key") != std::string::npos) ||
                (sDevName.find("ponkey_on") != std::string::npos)) {
                type = INDEV_TYPE_KEY;
            } else {
                continue;
            }
            if (type != INDEV_TYPE_UNKNOWN) {
                inputDevList.index = devIndex_;
                inputDevList.status = INPUT_DEVICE_STATUS_OPENED;
                inputDevList.fd = fd;
                detailInfo->devIndex = devIndex_;
                detailInfo->devType = type;
                (void)memcpy_s(&inputDevList.devPathNode, devPathNode.length(),
                    devPathNode.c_str(), devPathNode.length());
                (void)memcpy_s(&inputDevList.detailInfo, sizeof(InputDeviceInfo), detailInfo.get(),
                    sizeof(InputDeviceInfo));
                inputDevList_.insert_or_assign(devIndex_, inputDevList);
                devIndex_ += 1;
            }
        }
    }
}

int32_t InputDeviceManager::DoInputDeviceAction(void)
{
    struct input_event evtBuffer[EVENT_BUFFER_SIZE] {};
    int32_t result = 0;

    mEpollId_ = epoll_create1(EPOLL_CLOEXEC);
    if (mEpollId_ == INPUT_FAILURE) {
        HDF_LOGE("%{public}s: epoll create failed", __func__);
        return mEpollId_;
    }
    mInotifyId_ = inotify_init();
    result = inotify_add_watch(mInotifyId_, devPath_.c_str(), IN_DELETE | IN_CREATE);
    if (result == INPUT_FAILURE) {
        HDF_LOGE("%{public}s: add file watch failed", __func__);
        return result;
    }
    AddToEpoll(mEpollId_, mInotifyId_);
    while (true) {
        result = epoll_wait(mEpollId_, epollEventList_, EPOLL_MAX_EVENTS, EPOLL_WAIT_TIMEOUT);
        if (result <= 0) {
            continue;
        }
        for (int32_t i = 0; i < result; i++) {
            if (epollEventList_[i].data.fd != mInotifyId_) {
                DoRead(epollEventList_[i].data.fd, evtBuffer, EVENT_BUFFER_SIZE);
                continue;
            }
            if (INPUT_FAILURE == InotifyEventHandler(mEpollId_, mInotifyId_)) {
                HDF_LOGE("%{public}s: inotify handler failed", __func__);
                return INPUT_FAILURE;
            }
        }
    }
    return INPUT_SUCCESS;
}

void InputDeviceManager::DoWithEventDeviceAdd(int32_t &epollFd, int32_t &fd, string devPath)
{
    bool findDeviceFlag = false;
    uint32_t type {};
    uint32_t index {};
    uint32_t status {};

    std::shared_ptr<InputDeviceInfo> detailInfo = std::make_shared<InputDeviceInfo>();
    (void)memset_s(detailInfo.get(), sizeof(InputDeviceInfo), 0, sizeof(InputDeviceInfo));
    (void)GetInputDeviceInfo(fd, detailInfo.get());
    auto sDevName = string(detailInfo->attrSet.devName);
    for (auto it = inputDevList_.begin(); it != inputDevList_.end();) {
        if (string(it->second.detailInfo.attrSet.devName) == sDevName) {
            it->second.fd = fd;
            it->second.status = INPUT_DEVICE_STATUS_OPENED;
            findDeviceFlag = true;
            index = it->first;
            break;
        } else {
            ++it;
        }
    }
    if (sDevName.find("Keyboard") != std::string::npos) {
        detailInfo->devType = INDEV_TYPE_KEYBOARD;
    }
    if (sDevName.find("Mouse") != std::string::npos) {
        detailInfo->devType = INDEV_TYPE_MOUSE;
    }
    type = detailInfo->devType;
    if (!findDeviceFlag) {
        InputDevListNode inputDevList {};
        index = devIndex_;
        inputDevList.index = devIndex_;
        inputDevList.status = INPUT_DEVICE_STATUS_OPENED;
        inputDevList.fd = fd;
        detailInfo->devIndex = devIndex_;
        (void)memcpy_s(inputDevList.devPathNode, devPath.length(), devPath.c_str(), devPath.length());
        (void)memcpy_s(&inputDevList.detailInfo, sizeof(InputDeviceInfo), detailInfo.get(), sizeof(InputDeviceInfo));
        inputDevList_.insert_or_assign(devIndex_, inputDevList);
    }
    status = INPUT_DEVICE_STATUS_OPENED;
    SendHotPlugEvent(type, index, status);
    if (!findDeviceFlag) {
        devIndex_ += 1;
    }
}

void InputDeviceManager::SendHotPlugEvent(uint32_t &type, uint32_t &index, uint32_t status)
{
    // hot plug evnets happened
    InputHotPlugEvent *evtPlusPkg = (InputHotPlugEvent *)OsalMemAlloc(sizeof(InputHotPlugEvent));
    if (evtPlusPkg == nullptr) {
        HDF_LOGE("%{public}s: OsalMemAlloc failed", __func__);
        return;
    }

    evtPlusPkg->devType = type;
    evtPlusPkg->devIndex = index;
    evtPlusPkg->status = status;

    if (reportHotPlugEventCallback_ != nullptr) {
        HDF_LOGD("devType: %{public}u devIndex: %{public}u status: %{public}u", type, index, status);
        reportHotPlugEventCallback_->HotPlugCallback(evtPlusPkg);
    }

    OsalMemFree(evtPlusPkg);
    evtPlusPkg = nullptr;
}

void InputDeviceManager::DoWithEventDeviceDel(int32_t &epollFd, uint32_t &index)
{
    uint32_t type {};
    uint32_t devIndex {};
    uint32_t status {};

    CloseInputDevice(inputDevList_[index].devPathNode);
    RemoveEpoll(epollFd, inputDevList_[index].fd);
    HDF_LOGD("%{public}s: index: %{public}d fd: %{public}d devName: %{public}s", __func__,
             devIndex_, inputDevList_[index].fd, inputDevList_[index].detailInfo.attrSet.devName);

    // hot plug evnets happened
    auto sDevName = string(inputDevList_[index].detailInfo.attrSet.devName);
    if (sDevName.find("Keyboard") != std::string::npos) {
        type = INDEV_TYPE_KEYBOARD;
    }
    if (sDevName.find("Mouse") != std::string::npos) {
        type = INDEV_TYPE_MOUSE;
    }
    auto ret = FindIndexFromDevName(sDevName, &devIndex);
    if (ret != INPUT_SUCCESS) {
        HDF_LOGE("%{public}s: no found device maybe it has been removed", __func__);
        SendHotPlugEvent(type, devIndex_, status);
        return;
    }
    status = INPUT_DEVICE_STATUS_CLOSED;
    SendHotPlugEvent(type, devIndex, status);
    for (auto it = inputDevList_.begin(); it != inputDevList_.end();) {
        if (it->first == devIndex_) {
            it->second.fd = 0;
            it->second.status = INPUT_DEVICE_STATUS_CLOSED;
        } else {
            ++it;
        }
    }
}

int32_t InputDeviceManager::InotifyEventHandler(int32_t epollFd, int32_t notifyFd)
{
    char InfoBuf[BUFFER_SIZE];
    struct inotify_event *event {};
    char nodeRealPath[PATH_MAX + 1] = { '\0' };
    char *p {};
    int32_t tmpFd {};

    (void)memset_s(InfoBuf, BUFFER_SIZE, 0, BUFFER_SIZE);
    int32_t result = read(notifyFd, InfoBuf, BUFFER_SIZE);
    for (p = InfoBuf; p < InfoBuf + result;) {
        event = (struct inotify_event *)(p);
        auto nodePath = devPath_ + "/" + string(event->name);
        if (realpath(nodePath.c_str(), nodeRealPath) == nullptr) {
            HDF_LOGE("%{public}s: The absolute path does not exist.", __func__);
            return INPUT_FAILURE;
        }
        if (event->mask & IN_CREATE) {
            tmpFd = open(nodeRealPath, O_RDWR);
            if (tmpFd == INPUT_FAILURE) {
                HDF_LOGE("%{public}s: open file failure: %{public}s", __func__, nodeRealPath);
                return INPUT_FAILURE;
            }
            if (nodePath.find("event") == std::string::npos) {
                break;
            }
            DoWithEventDeviceAdd(epollFd, tmpFd, nodePath);
        } else if (event->mask & IN_DELETE) {
            for (auto &inputDev : inputDevList_) {
                if (!strcmp(inputDev.second.devPathNode, nodePath.c_str())) {
                    DoWithEventDeviceDel(epollFd, inputDev.second.index);
                    break;
                }
            }
        } else {
            // do nothing
            HDF_LOGI("%{public}s: others actions has done", __func__);
        }
        p += sizeof(struct inotify_event) + event->len;
    }
    return 0;
}

int32_t InputDeviceManager::AddToEpoll(int32_t epollFd, int32_t fileFd)
{
    int32_t result {0};
    struct epoll_event eventItem {};

    (void)memset_s(&eventItem, sizeof(eventItem), 0, sizeof(eventItem));
    eventItem.events = EPOLLIN;
    eventItem.data.fd = fileFd;
    result = epoll_ctl(epollFd, EPOLL_CTL_ADD, fileFd, &eventItem);
    return result;
}
void InputDeviceManager::RemoveEpoll(int32_t epollFd, int32_t fileFd)
{
    epoll_ctl(epollFd, EPOLL_CTL_DEL, fileFd, nullptr);
}

int32_t InputDeviceManager::FindIndexFromFd(int32_t &fd, uint32_t *index)
{
    std::lock_guard<std::mutex> guard(lock_);
    for (auto &inputDev : inputDevList_) {
        if (fd == inputDev.second.fd) {
            *index = inputDev.first;
            return INPUT_SUCCESS;
        }
    }
    return INPUT_FAILURE;
}

int32_t InputDeviceManager::FindIndexFromDevName(string devName, uint32_t *index)
{
    std::lock_guard<std::mutex> guard(lock_);
    for (auto &inputDev : inputDevList_) {
        if (!strcmp(devName.c_str(), inputDev.second.detailInfo.attrSet.devName)) {
            *index =  inputDev.first;
            return INPUT_SUCCESS;
        }
    }
    return INPUT_FAILURE;
}

// InputManager
RetStatus InputDeviceManager::ScanDevice(InputDevDesc *staArr, uint32_t arrLen)
{
    if (staArr == nullptr) {
        HDF_LOGE("%{public}s: param is null", __func__);
        return INPUT_NULL_PTR;
    }

    auto scanCount = (arrLen >= inputDevList_.size() ? inputDevList_.size() : arrLen);
    if (inputDevList_.size() == 0) {
        HDF_LOGE("%{public}s: inputDevList_.size is 0", __func__);
        return INPUT_FAILURE;
    }

    for (size_t i = 0; i <= scanCount; i++) {
        (staArr + i)->devIndex = inputDevList_[i].index;
        (staArr + i)->devType = inputDevList_[i].detailInfo.devType;
    }

    return INPUT_SUCCESS;
}

RetStatus InputDeviceManager::OpenDevice(uint32_t deviceIndex)
{
    std::lock_guard<std::mutex> guard(lock_);
    auto ret = INPUT_FAILURE;

    if (deviceIndex > MAX_SUPPORT_DEVS) {
        HDF_LOGE("%{public}s: param is wrong", __func__);
        return ret;
    }
    auto searchIndex = inputDevList_.find(deviceIndex);
    if (searchIndex != inputDevList_.end()) {
        if (searchIndex->second.status != INPUT_DEVICE_STATUS_OPENED) {
            auto openRet = OpenInputDevice(searchIndex->second.devPathNode);
            if (openRet > 0) {
                AddToEpoll(mEpollId_, openRet);
                ret = INPUT_SUCCESS;
            } else {
                HDF_LOGE("%{public}s: open error: %{public}d errormsg: %{public}s",
                         __func__, openRet, strerror(errno));
                return ret;
            }
            searchIndex->second.fd = openRet;
        } else {
            HDF_LOGD("%{public}s: open devPathNoth: %{public}s fd: %{public}d",
                     __func__, searchIndex->second.devPathNode, searchIndex->second.fd);
            HDF_LOGD("%{public}s: open devPathNoth: %{public}s status: %{public}d index: %{public}d",
                     __func__, searchIndex->second.devPathNode, searchIndex->second.status, searchIndex->first);
            AddToEpoll(mEpollId_, searchIndex->second.fd);
            ret = INPUT_SUCCESS;
        }
    }
    for (auto &e : inputDevList_) {
        dumpInfoList(e.second);
    }
    return ret;
}

RetStatus InputDeviceManager::CloseDevice(uint32_t deviceIndex)
{
    std::lock_guard<std::mutex> guard(lock_);
    auto ret = INPUT_FAILURE;

    if (deviceIndex > MAX_SUPPORT_DEVS) {
        HDF_LOGE("%{public}s: param is wrong", __func__);
        return ret;
    }
    auto searchIndex = inputDevList_.find(deviceIndex);
    if (searchIndex != inputDevList_.end()) {
        ret = CloseInputDevice(searchIndex->second.devPathNode);
    }
    HDF_LOGD("%{public}s: close devIndex: %{public}u ret: %{public}d inputDevList_ size:%{public}lu ",
             __func__, deviceIndex, ret, inputDevList_.size());
    return ret;
}

int32_t InputDeviceManager::GetDevice(int32_t deviceIndex, InputDeviceInfo **devInfo)
{
    std::lock_guard<std::mutex> guard(lock_);
    auto ret = INPUT_FAILURE;
    std::shared_ptr<InputDeviceInfo> detailInfo;

    if (devInfo == nullptr || deviceIndex > MAX_SUPPORT_DEVS) {
        HDF_LOGE("%{public}s: param is wrong", __func__);
        return INPUT_FAILURE;
    }
    for (size_t i = 0; i <= inputDevList_.size(); i++) {
        auto it = inputDevList_.find(deviceIndex);
        if (it != inputDevList_.end()) {
            detailInfo = std::make_shared<InputDeviceInfo>();
            (void)memset_s(detailInfo.get(), sizeof(InputDeviceInfo), 0, sizeof(InputDeviceInfo));
            (void)memcpy_s(detailInfo.get(), sizeof(InputDeviceInfo), &it->second.detailInfo, sizeof(InputDeviceInfo));
            *devInfo = detailInfo.get();
            ret = INPUT_SUCCESS;
        } else {
            continue;
        }
    }
    HDF_LOGD("%{public}s: devIndex: %{public}d ret: %{public}d", __func__, deviceIndex, ret);
    return ret;
}

int32_t InputDeviceManager::GetDeviceList(uint32_t *devNum, InputDeviceInfo **deviceList, uint32_t size)
{
    std::lock_guard<std::mutex> guard(lock_);

    auto scanCount = (size >= inputDevList_.size() ? inputDevList_.size() : size);
    if ((devNum == nullptr) || (deviceList == nullptr) || (*deviceList == nullptr)) {
        HDF_LOGE("%{public}s: null pointer", __func__);
        return INPUT_FAILURE;
    }
    if (inputDevList_.size() == 0) {
        HDF_LOGE("%{public}s: inputDevList_ size is 0", __func__);
        return INPUT_FAILURE;
    }
    for (size_t i = 0; i < scanCount; i++) {
        (void)memcpy_s((*deviceList) + i, sizeof(InputDeviceInfo), &inputDevList_[i].detailInfo,
            sizeof(InputDeviceInfo));
    }
    *devNum = inputDevList_.size();
    HDF_LOGD("%{public}s: devNum: %{public}u devIndex_: %{public}d", __func__, *devNum, devIndex_);

    return INPUT_SUCCESS;
}

// InputController
RetStatus InputDeviceManager::SetPowerStatus(uint32_t devIndex, uint32_t status)
{
    RetStatus rc = INPUT_SUCCESS;
    return rc;
}

RetStatus InputDeviceManager::GetPowerStatus(uint32_t devIndex, uint32_t *status)
{
    RetStatus rc = INPUT_SUCCESS;
    return rc;
}

RetStatus InputDeviceManager::GetDeviceType(uint32_t devIndex, uint32_t *deviceType)
{
    RetStatus rc = INPUT_SUCCESS;

    *deviceType = inputDevList_[devIndex].detailInfo.devType;
    HDF_LOGI("%{public}s: devType: %{public}u", __func__, *deviceType);
    return rc;
}

RetStatus InputDeviceManager::GetChipInfo(uint32_t devIndex, char *chipInfo, uint32_t length)
{
    RetStatus rc = INPUT_SUCCESS;

    (void)memcpy_s(chipInfo, length, inputDevList_[devIndex].detailInfo.chipInfo, length);
    HDF_LOGI("%{public}s: chipInfo: %{public}s", __func__, chipInfo);
    return rc;
}

RetStatus InputDeviceManager::GetVendorName(uint32_t devIndex, char *vendorName, uint32_t length)
{
    RetStatus rc = INPUT_SUCCESS;

    (void)memcpy_s(vendorName, length, inputDevList_[devIndex].detailInfo.vendorName, length);
    HDF_LOGI("%{public}s: vendorName: %{public}s", __func__, vendorName);
    return rc;
}

RetStatus InputDeviceManager::GetChipName(uint32_t devIndex, char *chipName, uint32_t length)
{
    RetStatus rc = INPUT_SUCCESS;

    (void)memcpy_s(chipName, length, inputDevList_[devIndex].detailInfo.chipName, length);
    HDF_LOGI("%{public}s: chipName: %{public}s", __func__, chipName);
    return rc;
}

RetStatus InputDeviceManager::SetGestureMode(uint32_t devIndex, uint32_t gestureMode)
{
    RetStatus rc = INPUT_SUCCESS;
    return rc;
}

RetStatus InputDeviceManager::RunCapacitanceTest(uint32_t devIndex, uint32_t testType, char *result, uint32_t length)
{
    RetStatus rc = INPUT_SUCCESS;
    return rc;
}

RetStatus InputDeviceManager::RunExtraCommand(uint32_t devIndex, InputExtraCmd *cmd)
{
    RetStatus rc = INPUT_SUCCESS;
    return rc;
}

// InputReporter
RetStatus InputDeviceManager::RegisterReportCallback(uint32_t devIndex, InputEventCb *callback)
{
    RetStatus rc = INPUT_SUCCESS;
    if (devIndex > MAX_SUPPORT_DEVS) {
        HDF_LOGE("%{public}s: param is wrong", __func__);
        return INPUT_FAILURE;
    }
    reportEventPkgCallback_[devIndex] = callback;
    return rc;
}

RetStatus InputDeviceManager::UnregisterReportCallback(uint32_t devIndex)
{
    HDF_LOGI("%{public}s: %{public}d dev is unregister", __func__, devIndex);
    RetStatus rc = INPUT_SUCCESS;
    if (devIndex > MAX_SUPPORT_DEVS) {
        HDF_LOGE("%{public}s: param is wrong", __func__);
        return INPUT_FAILURE;
    }
    reportEventPkgCallback_[devIndex] = nullptr;
    return rc;
}

RetStatus InputDeviceManager::RegisterHotPlugCallback(InputHostCb *callback)
{
    RetStatus rc = INPUT_SUCCESS;
    reportHotPlugEventCallback_ = callback;
    HDF_LOGI("%{public}s: called line %{public}d ret %{public}d", __func__, __LINE__, rc);
    return rc;
}

RetStatus InputDeviceManager::UnregisterHotPlugCallback(void)
{
    RetStatus rc = INPUT_SUCCESS;
    reportHotPlugEventCallback_ = nullptr;
    HDF_LOGI("%{public}s: called line %{public}d ret:%{public}d", __func__, __LINE__, rc);
    return rc;
}

void InputDeviceManager::WorkerThread()
{
    HDF_LOGI("%{public}s: called line %{public}d ", __func__, __LINE__);
    std::future<void> fuResult = std::async(std::launch::async, [this]() {
        DoInputDeviceAction();
        return;
    });
    fuResult.get();
}
}
}
