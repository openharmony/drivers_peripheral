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
#include "input_uhdf_log.h"
#include "osal_mem.h"
#include "securec.h"

#define HDF_LOG_TAG InputDeviceHdiManager

namespace OHOS {
namespace Input {
using namespace std;
constexpr uint32_t DEV_INDEX_MAX = 32;
constexpr uint32_t RELOAD_INTERVAL_MAX = 800;
const int32_t INVALID_ID = -1;
const int32_t MEMCPY_ERROR = -1;
const int32_t CREATE_SUCCESS = 1;
const int32_t CREATE_ERROR = 0;
void InputDeviceManager::Init()
{
    inputDevList_.clear();
    reportEventPkgCallBackLock_.lock();
    reportEventPkgCallback_.clear();
    reportEventPkgCallBackLock_.unlock();
    std::vector<std::string> flist = GetFiles(devPath_);
    LoadInputDevices(flist);
    std::thread reloadThread(&InputDeviceManager::ReloadInputDevices, this, flist);
    reloadThread.detach();
    std::thread t1([this] {this->WorkerThread();});
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
            OsalMemFree(eventPkgs[i]);
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

void InputDeviceManager::ReportEventPkg(int32_t iFd, InputEventPackage **iEvtPkg, size_t iCount)
{
    if (iEvtPkg == nullptr) {
        HDF_LOGE("%{public}s: param invalid, line: %{public}d", __func__, __LINE__);
        return;
    }
    std::lock_guard<std::mutex> guard(reportEventPkgCallBackLock_);
    for (auto &callbackFunc : reportEventPkgCallback_) {
        uint32_t index {0};
        auto ret = FindIndexFromFd(iFd, &index);
        if (callbackFunc.second != nullptr && ret != INPUT_FAILURE) {
            callbackFunc.second->EventPkgCallback(const_cast<const InputEventPackage **>(iEvtPkg), iCount, index);
        }
    }
    return;
}

int32_t CheckReadResult(int32_t readResult)
{
    if (readResult == 0 || (readResult < 0 && errno == ENODEV)) {
        return INPUT_FAILURE;
    }
    if (readResult < 0) {
        if (errno != EAGAIN && errno != EINTR) {
            HDF_LOGE("%{public}s: could not get event (errno = %{public}d)", __func__, errno);
        }
        return INPUT_FAILURE;
    }
    if ((readResult % sizeof(struct input_event)) != 0) {
        HDF_LOGE("%{public}s: could not get one event size %{public}lu readResult size: %{public}d", __func__,
            sizeof(struct input_event), readResult);
        return INPUT_FAILURE;
    }
    return INPUT_SUCCESS;
}

// read action
void InputDeviceManager::DoRead(int32_t fd, struct input_event *event, size_t size)
{
    int32_t readLen = read(fd, event, sizeof(struct input_event) * size);
    if (CheckReadResult(readLen) == INPUT_FAILURE) {
        return;
    }
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
            OsalMemFree(evtPkg);
            evtPkg = nullptr;
            return;
        }
        evtPkg[i]->type = iEvent.type;
        evtPkg[i]->code = iEvent.code;
        evtPkg[i]->value = iEvent.value;
        evtPkg[i]->timestamp = (uint64_t)iEvent.time.tv_sec * MS_THOUSAND * MS_THOUSAND +
                               (uint64_t)iEvent.time.tv_usec;
    }
    ReportEventPkg(fd, evtPkg, count);
    for (size_t i = 0; i < count; i++) {
        OsalMemFree(evtPkg[i]);
        evtPkg[i] = nullptr;
    }
    OsalMemFree(evtPkg);
    evtPkg = nullptr;
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
                inputDev.second.fd = -1;
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
        int32_t ret = strcpy_s(detailInfo->attrSet.devName, DEV_NAME_LEN, buffer);
        if (ret) {
            HDF_LOGE("%{public}s: strcpy_s failed, ret %{public}d", __func__, ret);
            return INPUT_FAILURE;
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
    for (uint32_t i = 0; i < BITS_TO_UINT64(ABS_CNT); i++) {
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

uint32_t GetInputDeviceTypeInfo(const string &devName)
{
    uint32_t type {INDEV_TYPE_UNKNOWN};
    if (devName.find("input_mt_wrapper") != std::string::npos) {
        type = INDEV_TYPE_TOUCH;
    } else if ((devName.find("Keyboard") != std::string::npos) &&
               (devName.find("Headset") == std::string::npos)) {
        type = INDEV_TYPE_KEYBOARD;
    } else if (devName.find("Mouse") != std::string::npos) {
        type = INDEV_TYPE_MOUSE;
    } else if ((devName.find("_gpio_key") != std::string::npos) ||
               (devName.find("ponkey_on") != std::string::npos)) {
        type = INDEV_TYPE_KEY;
    } else if (devName.find("Touchpad") != std::string::npos) {
        type = INDEV_TYPE_TOUCHPAD;
    }
    return type;
}

int32_t InputDeviceManager::GetCurDevIndex()
{
    if (inputDevList_.size() >= DEV_INDEX_MAX) {
        HDF_LOGE("%{public}s: The number of devices has reached max_num", __func__);
        return INVALID_ID;
    }
    if (inputDevList_.count(devIndex_) == 0) {
        return static_cast<int32_t>(devIndex_);
    }
    uint32_t newId = inputDevList_.size();
    while (inputDevList_.count(newId) != 0) {
        newId++;
    }
    return static_cast<int32_t>(newId);
}

int32_t InputDeviceManager::CreateInputDevListNode(InputDevListNode &inputDevNode, std::string &fileName)
{
    std::string devPathNode = devPath_ + "/" + fileName;
    std::string::size_type n = devPathNode.find("event");
    if (n == std::string::npos) {
        HDF_LOGE("%{public}s: not found event node", __func__);
        return CREATE_ERROR;
    }
    auto fd = OpenInputDevice(devPathNode);
    if (fd < 0) {
        HDF_LOGE("%{public}s: open node failed", __func__);
        return CREATE_ERROR;
    }
    std::shared_ptr<InputDeviceInfo> detailInfo = std::make_shared<InputDeviceInfo>();
    (void)memset_s(detailInfo.get(), sizeof(InputDeviceInfo), 0, sizeof(InputDeviceInfo));
    (void)GetInputDeviceInfo(fd, detailInfo.get());
    auto sDevName = string(detailInfo->attrSet.devName);
    uint32_t type = GetInputDeviceTypeInfo(sDevName);
    if (type == INDEV_TYPE_UNKNOWN) {
        close(fd);
        HDF_LOGE("%{public}s: input device type unknow: %{public}d", __func__, type);
        return CREATE_ERROR;
    }
    inputDevNode.index = devIndex_;
    inputDevNode.status = INPUT_DEVICE_STATUS_OPENED;
    inputDevNode.fd = fd;
    detailInfo->devIndex = devIndex_;
    detailInfo->devType = type;
    if (memcpy_s(&inputDevNode.devPathNode, devPathNode.length(),
        devPathNode.c_str(), devPathNode.length()) != EOK ||
        memcpy_s(&inputDevNode.detailInfo, sizeof(InputDeviceInfo), detailInfo.get(),
        sizeof(InputDeviceInfo)) != EOK) {
        close(fd);
        HDF_LOGE("%{public}s: memcpy_s failed, line: %{public}d", __func__, __LINE__);
        return MEMCPY_ERROR;
    }
    return CREATE_SUCCESS;
}

void InputDeviceManager::LoadInputDevices(std::vector<std::string> &flist)
{
    inputDevList_.clear();
    InputDevListNode inputDevNode {};

    for (unsigned i = 0; i < flist.size(); i++) {
        int32_t curDevIndex = GetCurDevIndex();
        if (curDevIndex == INVALID_ID) {
            return;
        }
        devIndex_ = static_cast<uint32_t>(curDevIndex);
        int32_t ret = CreateInputDevListNode(inputDevNode, flist[i]);
        if (ret == MEMCPY_ERROR) {
            return;
        }
        if (ret == CREATE_SUCCESS) {
            inputDevList_.insert_or_assign(devIndex_, inputDevNode);
            devIndex_ += 1;
        }
    }
}

void InputDeviceManager::ReloadInputDevices(std::vector<std::string> flist)
{
    // 线程等待，保证input节点创建完成
    std::this_thread::sleep_for(std::chrono::milliseconds(RELOAD_INTERVAL_MAX));
    std::vector<std::string> curFileList = GetFiles(devPath_);
    // 当前节点与首次加载数量不一致，需加载新的节点
    if (curFileList.size() <= flist.size()) {
        return;
    }
    InputDevListNode inputDevNode {};
    for (unsigned i = 0; i < curFileList.size(); i++) {
        if (std::find(flist.begin(), flist.end(), curFileList[i]) != flist.end()) {
            continue;
        }
        int32_t curDevIndex = GetCurDevIndex();
        if (curDevIndex == INVALID_ID) {
            return;
        }
        devIndex_ = static_cast<uint32_t>(curDevIndex);
        int32_t ret = CreateInputDevListNode(inputDevNode, flist[i]);
        if (ret == MEMCPY_ERROR) {
            return;
        }
        if (ret == CREATE_SUCCESS) {
            inputDevList_.insert_or_assign(devIndex_, inputDevNode);
            devIndex_ += 1;
        }
    }
}

void InputDeviceManager::GetInputDeviceInfoList()
{
    std::vector<std::string> flist = GetFiles(devPath_);
    LoadInputDevices(flist);
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

void InputDeviceManager::DeleteDevListNode(int index)
{
    for (auto it = inputDevList_.begin(); it != inputDevList_.end();) {
        if (it->first == (uint32_t)index) {
            it = inputDevList_.erase(it);
            if (devIndex_ < 1 || devIndex_ > DEV_INDEX_MAX) {
                return;
            }
            devIndex_ = it->first;
        } else {
            ++it;
        }
    }
    return;
}

int32_t InputDeviceManager::AddDeviceNodeToList(
    int32_t &epollFd, int32_t &fd, string devPath, std::shared_ptr<InputDeviceInfo> &detailInfo)
{
    if (epollFd < 0 || fd < 0) {
        HDF_LOGE("%{public}s: param invalid, %{public}d", __func__, __LINE__);
        return INPUT_FAILURE;
    }
    int32_t curDevIndex = GetCurDevIndex();
    if (curDevIndex == INVALID_ID) {
        HDF_LOGE("%{public}s: input device exceeds the maximum limit, %{public}d", __func__, __LINE__);
        return INPUT_FAILURE;
    }
    devIndex_ = static_cast<uint32_t>(curDevIndex);
    InputDevListNode inputDevList {};
    inputDevList.index = devIndex_;
    inputDevList.status = INPUT_DEVICE_STATUS_OPENED;
    inputDevList.fd = fd;
    detailInfo->devIndex = devIndex_;
    if (memcpy_s(inputDevList.devPathNode, devPath.length(), devPath.c_str(), devPath.length()) != EOK ||
        memcpy_s(&inputDevList.detailInfo, sizeof(InputDeviceInfo), detailInfo.get(),
        sizeof(InputDeviceInfo)) != EOK) {
        HDF_LOGE("%{public}s: memcpy_s failed, line: %{public}d", __func__, __LINE__);
        return INPUT_FAILURE;
    }
    inputDevList_.insert_or_assign(devIndex_, inputDevList);
    if (AddToEpoll(epollFd, inputDevList.fd) != INPUT_SUCCESS) {
        HDF_LOGE("%{public}s: add to epoll failed, line: %{public}d", __func__, __LINE__);
        DeleteDevListNode(devIndex_);
        return INPUT_FAILURE;
    }
    devIndex_ += 1;
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
        if (string(it->second.devPathNode) == devPath && string(it->second.detailInfo.attrSet.devName) == sDevName) {
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
        if (AddDeviceNodeToList(epollFd, fd, devPath, detailInfo) != INPUT_SUCCESS) {
            HDF_LOGE("%{public}s: add device node failed, line: %{public}d", __func__, __LINE__);
            return;
        }
    }
    status = INPUT_DEVICE_STATUS_OPENED;
    SendHotPlugEvent(type, index, status);
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

    HDF_LOGD("%{public}s: index: %{public}d fd: %{public}d devName: %{public}s", __func__,
             index, inputDevList_[index].fd, inputDevList_[index].detailInfo.attrSet.devName);

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
    CloseInputDevice(inputDevList_[index].devPathNode);
    DeleteDevListNode(index);
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
        if (event->mask & IN_CREATE) {
            if (realpath(nodePath.c_str(), nodeRealPath) == nullptr) {
                HDF_LOGE("%{public}s: The absolute path does not exist.", __func__);
                return INPUT_FAILURE;
            }
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
    for (const auto &inputDev : inputDevList_) {
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
    for (const auto &inputDev : inputDevList_) {
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

    if (deviceIndex >= inputDevList_.size()) {
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

    if (deviceIndex >= inputDevList_.size()) {
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

    if (devInfo == nullptr || deviceIndex >= static_cast<int32_t>(inputDevList_.size()) || *devInfo != nullptr) {
        HDF_LOGE("%{public}s: param is wrong", __func__);
        return ret;
    }
    auto it = inputDevList_.find(deviceIndex);
    if (it != inputDevList_.end()) {
        int inputDeviceInfoSize = sizeof(InputDeviceInfo);
        *devInfo = reinterpret_cast<InputDeviceInfo *>(OsalMemAlloc(inputDeviceInfoSize));
        if (*devInfo == nullptr) {
            HDF_LOGE("%{public}s: %{public}d OsalMemAlloc failed", __func__, __LINE__);
            return ret;
        }
        if (memcpy_s(*devInfo, inputDeviceInfoSize, &it->second.detailInfo, inputDeviceInfoSize) != EOK) {
            OsalMemFree(*devInfo);
            HDF_LOGE("%{public}s: memcpy_s failed, line: %{public}d", __func__, __LINE__);
            return ret;
        }
        ret = INPUT_SUCCESS;
    }
    HDF_LOGD("%{public}s: devIndex: %{public}d ret: %{public}d", __func__, deviceIndex, ret);
    return ret;
}

int32_t InputDeviceManager::GetDeviceList(uint32_t *devNum, InputDeviceInfo **deviceList, uint32_t size)
{
    std::lock_guard<std::mutex> guard(lock_);
    auto ret = INPUT_FAILURE;

    auto scanCount = (size >= inputDevList_.size() ? inputDevList_.size() : size);
    if ((devNum == nullptr) || (deviceList == nullptr) || inputDevList_.size() == 0 || *deviceList != nullptr) {
        HDF_LOGE("%{public}s: param is wrong", __func__);
        return ret;
    }

    int inputDeviceInfoSize = sizeof(InputDeviceInfo);
    *deviceList = reinterpret_cast<InputDeviceInfo *>(OsalMemAlloc(inputDeviceInfoSize * scanCount));
    if (*deviceList == nullptr) {
        HDF_LOGE("%{public}s: %{public}d OsalMemAlloc failed", __func__, __LINE__);
        return ret;
    }
    for (size_t i = 0; i < scanCount; i++) {
        if (memcpy_s((*deviceList) + i, inputDeviceInfoSize, &inputDevList_[i].detailInfo, inputDeviceInfoSize) !=
            EOK) {
            OsalMemFree(*deviceList);
            HDF_LOGE("%{public}s: memcpy_s failed, line: %{public}d", __func__, __LINE__);
            return ret;
        }
    }
    *devNum = inputDevList_.size();
    ret = INPUT_SUCCESS;
    HDF_LOGD("%{public}s: devNum: %{public}u devIndex_: %{public}d", __func__, *devNum, devIndex_);

    return ret;
}

// InputController
RetStatus InputDeviceManager::SetPowerStatus(uint32_t devIndex, uint32_t status)
{
    RetStatus rc = INPUT_SUCCESS;
    if ((devIndex >= inputDevList_.size()) || (status >= INPUT_POWER_STATUS_UNKNOWN)) {
        HDF_LOGE("%{public}s: param is wrong", __func__);
        return INPUT_FAILURE;
    }
    return rc;
}

RetStatus InputDeviceManager::GetPowerStatus(uint32_t devIndex, uint32_t *status)
{
    RetStatus rc = INPUT_SUCCESS;
    if ((devIndex >= inputDevList_.size()) || (status == nullptr)) {
        HDF_LOGE("%{public}s: param is wrong", __func__);
        return INPUT_FAILURE;
    }
    return rc;
}

RetStatus InputDeviceManager::GetDeviceType(uint32_t devIndex, uint32_t *deviceType)
{
    RetStatus rc = INPUT_SUCCESS;
    if ((devIndex >= inputDevList_.size()) || (deviceType == nullptr)) {
        HDF_LOGE("%{public}s: param is wrong", __func__);
        return INPUT_FAILURE;
    }

    *deviceType = inputDevList_[devIndex].detailInfo.devType;
    HDF_LOGI("%{public}s: devType: %{public}u", __func__, *deviceType);
    return rc;
}

RetStatus InputDeviceManager::GetChipInfo(uint32_t devIndex, char *chipInfo, uint32_t length)
{
    RetStatus rc = INPUT_SUCCESS;
    if ((devIndex >= inputDevList_.size()) || (chipInfo == nullptr)) {
        HDF_LOGE("%{public}s: param is wrong", __func__);
        return INPUT_FAILURE;
    }

    if (memcpy_s(chipInfo, length, inputDevList_[devIndex].detailInfo.chipInfo, length) != EOK) {
        HDF_LOGE("%{public}s: memcpy_s failed, line: %{public}d", __func__, __LINE__);
        rc = INPUT_FAILURE;
    }
    HDF_LOGI("%{public}s: chipInfo: %{public}s", __func__, chipInfo);
    return rc;
}

RetStatus InputDeviceManager::GetVendorName(uint32_t devIndex, char *vendorName, uint32_t length)
{
    RetStatus rc = INPUT_SUCCESS;
    if ((devIndex >= inputDevList_.size()) || (vendorName == nullptr)) {
        HDF_LOGE("%{public}s: param is wrong", __func__);
        return INPUT_FAILURE;
    }

    if (memcpy_s(vendorName, length, inputDevList_[devIndex].detailInfo.vendorName, length) != EOK) {
        HDF_LOGE("%{public}s: memcpy_s failed, line: %{public}d", __func__, __LINE__);
        rc = INPUT_FAILURE;
    }
    HDF_LOGI("%{public}s: vendorName: %{public}s", __func__, vendorName);
    return rc;
}

RetStatus InputDeviceManager::GetChipName(uint32_t devIndex, char *chipName, uint32_t length)
{
    RetStatus rc = INPUT_SUCCESS;
    if ((devIndex >= inputDevList_.size()) || (chipName == nullptr)) {
        HDF_LOGE("%{public}s: param is wrong", __func__);
        return INPUT_FAILURE;
    }

    if (memcpy_s(chipName, length, inputDevList_[devIndex].detailInfo.chipName, length) != EOK) {
        HDF_LOGE("%{public}s: memcpy_s failed, line: %{public}d", __func__, __LINE__);
        rc = INPUT_FAILURE;
    }
    HDF_LOGI("%{public}s: chipName: %{public}s", __func__, chipName);
    return rc;
}

RetStatus InputDeviceManager::SetGestureMode(uint32_t devIndex, uint32_t gestureMode)
{
    RetStatus rc = INPUT_SUCCESS;
    if ((devIndex >= inputDevList_.size())) {
        HDF_LOGE("%{public}s: param is wrong", __func__);
        return INPUT_FAILURE;
    }
    return rc;
}

RetStatus InputDeviceManager::RunCapacitanceTest(uint32_t devIndex, uint32_t testType, char *result, uint32_t length)
{
    RetStatus rc = INPUT_SUCCESS;
    if ((devIndex >= inputDevList_.size()) || (testType >= TEST_TYPE_UNKNOWN) ||
        (result == nullptr) || (length < SELF_TEST_RESULT_LEN)) {
        HDF_LOGE("%{public}s: param is wrong", __func__);
        return INPUT_FAILURE;
    }
    return rc;
}

RetStatus InputDeviceManager::RunExtraCommand(uint32_t devIndex, InputExtraCmd *cmd)
{
    RetStatus rc = INPUT_SUCCESS;
    if ((devIndex >= inputDevList_.size()) || (cmd == nullptr) || (cmd->cmdCode == nullptr ||
        (cmd->cmdValue == nullptr))) {
        HDF_LOGE("%{public}s: param is wrong", __func__);
        return INPUT_FAILURE;
    }
    return rc;
}

// InputReporter
RetStatus InputDeviceManager::RegisterReportCallback(uint32_t devIndex, InputEventCb *callback)
{
    RetStatus rc = INPUT_SUCCESS;
    if ((devIndex >= inputDevList_.size()) || (callback == nullptr) || (callback->EventPkgCallback == nullptr)) {
        HDF_LOGE("%{public}s: param is wrong", __func__);
        return INPUT_FAILURE;
    }
    std::lock_guard<std::mutex> guard(reportEventPkgCallBackLock_);
    reportEventPkgCallback_[devIndex] = callback;
    return rc;
}

RetStatus InputDeviceManager::UnregisterReportCallback(uint32_t devIndex)
{
    HDF_LOGI("%{public}s: %{public}d dev is unregister", __func__, devIndex);
    RetStatus rc = INPUT_SUCCESS;
    if (devIndex >= inputDevList_.size()) {
        HDF_LOGE("%{public}s: param is wrong", __func__);
        return INPUT_FAILURE;
    }
    std::lock_guard<std::mutex> guard(reportEventPkgCallBackLock_);
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
