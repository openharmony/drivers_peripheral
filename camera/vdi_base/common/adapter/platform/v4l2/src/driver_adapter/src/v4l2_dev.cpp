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

#include "v4l2_dev.h"
#include <sys/prctl.h>

namespace OHOS::Camera {
std::map<std::string, std::string> HosV4L2Dev::deviceMatch = HosV4L2Dev::CreateDevMap();
std::map<std::string, int> HosV4L2Dev::fdMatch = HosV4L2Dev::CreateFdMap();
std::mutex HosV4L2Dev::deviceFdLock_ = {};

#ifndef V4L2_EMULATOR
  static constexpr uint32_t WATING_TIME = 1000 * 100;
#endif
HosV4L2Dev::HosV4L2Dev() {}
HosV4L2Dev::~HosV4L2Dev() {}

int HosV4L2Dev::GetCurrentFd(const std::string& cameraID)
{
    auto itr = HosV4L2Dev::fdMatch.find(cameraID);
    if (itr == HosV4L2Dev::fdMatch.end()) {
        CAMERA_LOGE("error: GetCurrentFd no camera fd\n");
        return RCERRORFD;
    }

    return itr->second;
}

RetCode HosV4L2Dev::start(const std::string& cameraID)
{
    std::string devName;
    int fd;

    CAMERA_LOGI("HosV4L2Dev::start enter %{public}s\n", cameraID.c_str());

    if (myFileFormat_ == nullptr) {
        myFileFormat_ = std::make_shared<HosFileFormat>();
        if (myFileFormat_ == nullptr) {
            CAMERA_LOGE("error: InitMatch: myFileFormat_ make_shared is NULL\n");
            return RC_ERROR;
        }
    }

    auto itr = HosV4L2Dev::deviceMatch.find(cameraID);
    if (itr == HosV4L2Dev::deviceMatch.end()) {
        CAMERA_LOGE("error:find V4L2 devname fail\n");
        return RC_ERROR;
    }
    devName = itr->second;

    fd = myFileFormat_->V4L2OpenDevice(devName);
    if (fd < 0) {
        CAMERA_LOGE("error:myFileFormat_->V4L2OpenDevice fail fd == %{public}d\n", fd);
        return RC_ERROR;
    }

    bufferType_ = static_cast<enum v4l2_buf_type>(myFileFormat_->V4L2SearchBufType(fd));
    if (bufferType_ == V4L2_BUF_TYPE_PRIVATE) {
        CAMERA_LOGE("error:myFileFormat_->V4L2SearchBufType bufferType_ == 0\n");
        return RC_ERROR;
    }

    std::lock_guard<std::mutex> l(HosV4L2Dev::deviceFdLock_);
    HosV4L2Dev::fdMatch.insert(std::make_pair(cameraID, fd));
    CAMERA_LOGI("HosV4L2Dev::start out cameraID:%{public}s, devName:%{public}s\n", cameraID.c_str(), devName.c_str());
    return RC_OK;
}

RetCode HosV4L2Dev::stop(const std::string& cameraID)
{
    int fd;

    CAMERA_LOGI("HosV4L2Dev::stop enter %{public}s\n", cameraID.c_str());

    if (myFileFormat_ == nullptr) {
        CAMERA_LOGE("HosV4L2Dev::stop myFileFormat_ == nullptr\n");
        return RC_ERROR;
    }

    auto itr = HosV4L2Dev::fdMatch.find(cameraID);
    if (itr == HosV4L2Dev::fdMatch.end()) {
        CAMERA_LOGE("HosV4L2Dev::stop GetCurrentFd error\n");
        return RC_ERROR;
    }

    fd = itr->second;
    if (fd < 0) {
        CAMERA_LOGE("HosV4L2Dev::stop fd error = %d\n", fd);
        return RC_ERROR;
    }

    myFileFormat_->V4L2CloseDevice(fd);

    std::lock_guard<std::mutex> l(HosV4L2Dev::deviceFdLock_);
    HosV4L2Dev::fdMatch.erase(itr);
    CAMERA_LOGI("HosV4L2Dev::stop out %{public}s\n", cameraID.c_str());
    return RC_OK;
}

RetCode HosV4L2Dev::Init(const std::vector<std::string>& cameraIDs)
{
    CAMERA_LOGI("HosV4L2Dev::Init enter\n");
    auto myFileFormat = std::make_shared<HosFileFormat>();
    if (myFileFormat == nullptr) {
        CAMERA_LOGE("error: InitMatch: myFileFormat_ make_shared is NULL\n");
        return RC_ERROR;
    }

    myFileFormat->V4L2MatchDevice(cameraIDs);
    CAMERA_LOGI("HosV4L2Dev::Init out\n");
    return RC_OK;
}

RetCode HosV4L2Dev::ReqBuffers(const std::string& cameraID, unsigned int buffCont)
{
    int rc, fd;
    CAMERA_LOGI("HosV4L2Dev::ReqBuffers enters %{public}s\n", cameraID.c_str());
    fd = GetCurrentFd(cameraID);
    if (fd < 0) {
        CAMERA_LOGE("error: ReqBuffers: GetCurrentFd error\n");
        return RC_ERROR;
    }

    if (myBuffers_ == nullptr) {
        myBuffers_ = HosV4L2Buffers::CreateHosV4L2Buffers(memoryType_, bufferType_);
        if (myBuffers_ == nullptr) {
            CAMERA_LOGE("error: Creatbuffer: myBuffers_ make_shared is NULL\n");
            return RC_ERROR;
        }
    }

    rc = myBuffers_->V4L2ReqBuffers(fd, buffCont);
    if (rc == RC_ERROR) {
        CAMERA_LOGE("error: Creatbuffer: V4L2ReqBuffers error\n");
        return RC_ERROR;
    }
    CAMERA_LOGI("HosV4L2Dev::ReqBuffers exit %{public}s\n", cameraID.c_str());
    return RC_OK;
}

RetCode HosV4L2Dev::CreatBuffer(const std::string& cameraID, const std::shared_ptr<FrameSpec>& frameSpec)
{
    int rc, fd;
    CAMERA_LOGI("HosV4L2Dev::CreatBuffer in %{public}s\n", cameraID.c_str());
    fd = GetCurrentFd(cameraID);
    if (fd < 0) {
        CAMERA_LOGE("error: ReqBuffers: GetCurrentFd error\n");
        return RC_ERROR;
    }

    if (frameSpec == nullptr || myBuffers_ == nullptr) {
        CAMERA_LOGE("error: Creatbuffer frameSpec or myBuffers_ is NULL\n");
        return RC_ERROR;
    }

    CAMERA_LOGI("Creatbuffer frameSpec->buffer index == %d\n", frameSpec->buffer_->GetIndex());

    rc = myBuffers_->V4L2AllocBuffer(fd, frameSpec);
    if (rc == RC_ERROR) {
        CAMERA_LOGE("error: Creatbuffer: V4L2AllocBuffer error\n");
        return RC_ERROR;
    }

    rc = myBuffers_->V4L2QueueBuffer(fd, frameSpec);
    if (rc == RC_ERROR) {
        CAMERA_LOGE("error: Creatbuffer: V4L2QueueBuffer error\n");
        return RC_ERROR;
    }
    CAMERA_LOGI("HosV4L2Dev::CreatBuffer out %{public}s\n", cameraID.c_str());
    return RC_OK;
}

RetCode HosV4L2Dev::QueueBuffer(const std::string& cameraID, const std::shared_ptr<FrameSpec>& frameSpec)
{
    int rc, fd;
    CAMERA_LOGI("HosV4L2Dev::QueueBuffer in %{public}s\n", cameraID.c_str());
    fd = GetCurrentFd(cameraID);
    if (fd < 0) {
        CAMERA_LOGE("QueueBuffer: GetCurrentFd error\n");
        return RC_ERROR;
    }

    if (frameSpec == nullptr || myBuffers_ == nullptr) {
        CAMERA_LOGE(" QueueBuffer frameSpec or myBuffers_ is NULL\n");
        return RC_ERROR;
    }

    rc = myBuffers_->V4L2QueueBuffer(fd, frameSpec);
    if (rc == RC_ERROR) {
        CAMERA_LOGE("QueueBuffer: V4L2QueueBuffer error\n");
        return RC_ERROR;
    }
    CAMERA_LOGI("HosV4L2Dev::QueueBuffer out %{public}s\n", cameraID.c_str());
    return RC_OK;
}

RetCode HosV4L2Dev::ReleaseBuffers(const std::string& cameraID)
{
    int fd;
    int rc = 0;
    CAMERA_LOGI("HosV4L2Dev::ReleaseBuffers in %{public}s\n", cameraID.c_str());
    if (myBuffers_ == nullptr) {
        CAMERA_LOGE("ReleaseBuffers myBuffers_ is NULL\n");
        return RC_ERROR;
    }

    fd = GetCurrentFd(cameraID);
    if (fd < 0) {
        CAMERA_LOGE("ReleaseBuffers: GetCurrentFd error\n");
        return RC_ERROR;
    }

    rc = myBuffers_->V4L2ReleaseBuffers(fd);
    if (rc == RC_ERROR) {
        CAMERA_LOGE("ReleaseBuffers: V4L2ReleaseBuffers error\n");
        return RC_ERROR;
    }
    CAMERA_LOGI("HosV4L2Dev::ReleaseBuffers out %{public}s\n", cameraID.c_str());
    return RC_OK;
}

#ifndef V4L2_EMULATOR
void HosV4L2Dev::dequeueBuffers()
{
    int nfds;
    int rc;
    struct epoll_event events[MAXSTREAMCOUNT];
    nfds = epoll_wait(epollFd_, events, MAXSTREAMCOUNT, -1);
    CAMERA_LOGI("loopBuffers: epoll_wait rc = %{public}d streamNumber_ == %{public}d\n", nfds, streamNumber_);

    for (int n = 0; nfds > 0; ++n, --nfds) {
        if ((events[n].events & EPOLLIN) && (events[n].data.fd != eventFd_)) {
            CHECK_IF_PTR_NULL_RETURN_VOID(myBuffers_);
            rc = myBuffers_->V4L2DequeueBuffer(events[n].data.fd);
            if (rc == RC_ERROR) {
                continue;
            }
        } else {
            CAMERA_LOGI("loopBuffers: epoll invalid events = 0x%{public}x or eventFd exit = %{public}d\n",
                events[n].events, (events[n].data.fd == eventFd_));
            usleep(WATING_TIME);
        }
    }
}
#endif

void HosV4L2Dev::loopBuffers()
{
#ifndef V4L2_EMULATOR
    CAMERA_LOGI("!!! loopBuffers enter, streamNumber_=%{public}d\n", streamNumber_);
#else
    int rc;
    int fd = deviceFd_;

    CAMERA_LOGI("!!! loopBuffers enter, streamNumber_=%{public}d, fd = %d", streamNumber_, fd);
#endif
    prctl(PR_SET_NAME, "v4l2_loopbuffer");

    while (true) {
        {
            std::lock_guard<std::mutex> l(streamLock_);
            if (streamNumber_ <= 0) {
                break;
            }
        }
#ifndef V4L2_EMULATOR
        dequeueBuffers();
#else
        CHECK_IF_PTR_NULL_RETURN_VOID(myBuffers_);
        rc = myBuffers_->V4L2DequeueBuffer(fd);
        if (rc == RC_ERROR) {
            CAMERA_LOGE("loopBuffers: myBuffers_->V4L2DequeueBuffer return error %d", rc);
        }
        constexpr int SleepTimeUs = 1000;
        usleep(SleepTimeUs);
#endif
    }
    CAMERA_LOGI("!!! loopBuffers exit, streamNumber_=%{public}d\n", streamNumber_);
}

RetCode HosV4L2Dev::CreateEpoll(int fd, const unsigned int streamNumber)
{
    struct epoll_event epollevent = {};
    CAMERA_LOGI("CreateEpoll enter, fd=%{public}d\n", fd);
    if (streamNumber == 0) {
        epollFd_ = epoll_create(MAXSTREAMCOUNT);
        if (epollFd_ < 0) {
            CAMERA_LOGE("V4L2 StartStream create_epoll failed\n");
            return RC_ERROR;
        }
        epollevent.events = EPOLLIN;
        epollevent.data.fd = fd;
        int ret = epoll_ctl(epollFd_, EPOLL_CTL_ADD, fd, &epollevent);
        if (ret < 0) {
            CAMERA_LOGE("add fd=%{public}d to epoll failed, ret=%{public}d, errno=%{public}d", fd, ret, errno);
        }

        std::lock_guard<std::mutex> l(epollLock_);
        epollEvent_.push_back(epollevent);

        eventFd_ = eventfd(0, 0);
        epollevent = {};
        epollevent.events = EPOLLIN;
        epollevent.data.fd = eventFd_;
        ret = epoll_ctl(epollFd_, EPOLL_CTL_ADD, eventFd_, &epollevent);
        if (ret < 0) {
            CAMERA_LOGE("add eventFd_=%{public}d to epoll failed, ret=%{public}d, errno=%{public}d",
                eventFd_, ret, errno);
            return RC_ERROR;
        }
    } else {
        epollevent.events = EPOLLIN;
        epollevent.data.fd = fd;

        std::lock_guard<std::mutex> l(epollLock_);
        epollEvent_.push_back(epollevent);

        int ret = epoll_ctl(epollFd_, EPOLL_CTL_ADD, fd, &epollevent);
        if (ret < 0) {
            CAMERA_LOGE("add fd = %{public}d to epoll failed, ret=%{public}d, errno=%{public}d", fd, ret, errno);
            return RC_ERROR;
        }
    }
    CAMERA_LOGI("CreateEpoll out, fd=%{public}d\n", fd);
    return RC_OK;
}

void HosV4L2Dev::EraseEpoll(int fd)
{
    CAMERA_LOGI("EraseEpoll enter, fd = %{public}d\n", fd);
    auto itr = std::find_if(epollEvent_.begin(), epollEvent_.end(), [fd](const epoll_event& event) {
        if (event.data.fd == fd) {
            return true;
        } else {
            return false;
        }
    });
    if (itr != epollEvent_.end()) {
        struct epoll_event event = *itr;
        int ret = epoll_ctl(epollFd_, EPOLL_CTL_DEL, fd, &event);
        if (ret < 0) {
            CAMERA_LOGE("del fd=%{public}d to epoll failed, ret=%{public}d, errno=%{public}d", fd, ret, errno);
        }
        std::lock_guard<std::mutex> l(epollLock_);
        epollEvent_.erase(itr);
    }
    CAMERA_LOGI("EraseEpoll out, fd = %{public}d\n", fd);
}

RetCode HosV4L2Dev::StartStream(const std::string& cameraID)
{
    int rc, fd;
    CAMERA_LOGI("StartStream enter, cameraID = %{public}s\n", cameraID.c_str());
    fd = GetCurrentFd(cameraID);
    if (fd < 0) {
        CAMERA_LOGE("error: ReqBuffers: GetCurrentFd error\n");
        return RC_ERROR;
    }
#ifdef V4L2_EMULATOR
    deviceFd_ = fd;
#endif

    if (myStreams_ == nullptr) {
        myStreams_ = std::make_shared<HosV4L2Streams>(bufferType_);
        if (myStreams_ == nullptr) {
            CAMERA_LOGE("error: StartStream: myStreams_ make_shared is NULL\n");
            return RC_ERROR;
        }
    }

    rc = myStreams_->V4L2StreamOn(fd);
    if (rc == RC_ERROR) {
        CAMERA_LOGE("error: StartStream: V4L2StreamOn error\n");
        return RC_ERROR;
    }

    rc = CreateEpoll(fd, streamNumber_);
    if (rc == RC_ERROR) {
        CAMERA_LOGE("StartStream: CreateEpoll error\n");
        return RC_ERROR;
    }

    if (streamNumber_ == 0) {
        streamNumber_++;
        CAMERA_LOGE("go start thread loopBuffers, streamNumber_=%{public}d\n", streamNumber_);
        streamThread_ = new (std::nothrow) std::thread([this] {this->loopBuffers();});
        if (streamThread_ == nullptr) {
            CAMERA_LOGE("V4L2 StartStream start thread failed\n");
            streamNumber_--;
            return RC_ERROR;
        }
    }
    CAMERA_LOGI("StartStream out, cameraID = %{public}s\n", cameraID.c_str());
    return RC_OK;
}

RetCode HosV4L2Dev::StopStream(const std::string& cameraID)
{
    CAMERA_LOGI("StartStream enter, cameraID = %{public}s\n", cameraID.c_str());
    if (myStreams_ == nullptr || streamThread_ == nullptr) {
        CAMERA_LOGE("error: StopStream: myStreams_ or streamThread_ is nullptr");
        return RC_ERROR;
    }

    int fd = GetCurrentFd(cameraID);
    if (fd < 0) {
        CAMERA_LOGE("error: StopStream: GetCurrentFd error\n");
        return RC_ERROR;
    }

    unsigned int streamNum = 0;
    {
        std::lock_guard<std::mutex> l(streamLock_);
        streamNum = --streamNumber_;
        CAMERA_LOGI("HosV4L2Dev::StopStream streamNumber_ = %{public}d\n", streamNumber_);
    }

    if (streamNum == 0) {
        CAMERA_LOGI("waiting loopBuffers stop\n");
        uint64_t one = 1;
        ssize_t ret = write(eventFd_, &one, sizeof(one));
        if (ret != sizeof(one)) {
            CAMERA_LOGE("HosV4L2Dev::StopStream write fd: %{public}d, failed, ret = %{public}zd\n", eventFd_, ret);
        }
        streamThread_->join();
        close(eventFd_);
        CAMERA_LOGI("waiting loopBuffers exit\n");
    }

    if (myStreams_->V4L2StreamOff(fd) == RC_ERROR) {
        CAMERA_LOGE("error: StopStream: V4L2StreamOn error\n");
        return RC_ERROR;
    }

    EraseEpoll(fd);
    {
        std::lock_guard<std::mutex> l(streamLock_);
        if (streamNumber_ == 0) {
            close(epollFd_);
            delete streamThread_;
            streamThread_ = nullptr;
        }
    }
    CAMERA_LOGI("StartStream out, cameraID = %{public}s\n", cameraID.c_str());
    return RC_OK;
}

void SetCtrlByCondition(int32_t fd, AdapterCmd command, const int* args,
    int &rc, std::shared_ptr<HosV4L2Control> myControl_)
{
    switch (command) {
        case CMD_EXPOSURE_MODE:
            rc = myControl_->V4L2SetCtrl(fd, V4L2_CID_EXPOSURE_AUTO, *args);
            break;
        case CMD_AE_EXPOTIME:
            rc = myControl_->V4L2SetCtrl(fd, V4L2_CID_EXPOSURE_ABSOLUTE, *args);
            break;
        case CMD_EXPOSURE_COMPENSATION:
            rc = myControl_->V4L2SetCtrl(fd, V4L2_CID_EXPOSURE, *args);
            break;
        case CMD_AWB_MODE:
            rc = myControl_->V4L2SetCtrl(fd, V4L2_CID_AUTO_N_PRESET_WHITE_BALANCE, *args);
            break;
        case CMD_AE_LOCK:
        case CMD_EXPOSURE_LOCK:
        case CMD_FOCUS_LOCK:
        case CMD_AWB_LOCK:
            rc = myControl_->V4L2SetCtrl(fd, V4L2_CID_3A_LOCK, *args);
            break;
        case CMD_FOCUS_AUTO:
            rc = myControl_->V4L2SetCtrl(fd, V4L2_CID_FOCUS_AUTO, *args);
            break;
        case CMD_FOCUS_ABSOLUTE:
            rc = myControl_->V4L2SetCtrl(fd, V4L2_CID_FOCUS_ABSOLUTE, *args);
            break;
        case CMD_AUTO_FOCUS_START:
            rc = myControl_->V4L2SetCtrl(fd, V4L2_CID_AUTO_FOCUS_START, *args);
            break;
        case CMD_AUTO_FOCUS_STOP:
            rc = myControl_->V4L2SetCtrl(fd, V4L2_CID_AUTO_FOCUS_STOP, *args);
            break;
        case CMD_METER_MODE:
            rc = myControl_->V4L2SetCtrl(fd, V4L2_CID_EXPOSURE_METERING, *args);
            break;
        case CMD_FLASH_MODE:
            rc = myControl_->V4L2SetCtrl(fd, V4L2_CID_FLASH_LED_MODE, *args);
            break;
        case CMD_AE_EXPO:
            rc = myControl_->V4L2SetCtrl(fd, V4L2_CID_BRIGHTNESS, *args);
            break;
        default:
            break;
    }
}

RetCode HosV4L2Dev::UpdateSetting(const std::string& cameraID, AdapterCmd command, const int* args)
{
    CAMERA_LOGI("UpdateSetting enter, cameraID = %{public}s\n", cameraID.c_str());
    int32_t fd;
    int rc = 0;
    if (args == nullptr) {
        CAMERA_LOGE("HosV4L2Dev::UpdateSetting: args is NULL\n");
        return RC_ERROR;
    }
    if (myControl_ == nullptr) {
        myControl_ = std::make_shared<HosV4L2Control>();
        if (myControl_ == nullptr) {
            CAMERA_LOGE("HosV4L2Dev::UpdateSetting: myControl_ make_shared is NULL\n");
            return RC_ERROR;
        }
    }
    fd = GetCurrentFd(cameraID);
    if (fd < 0) {
        CAMERA_LOGE("UpdateSetting: GetCurrentFd error\n");
        return RC_ERROR;
    }
    SetCtrlByCondition(fd, command, args, rc, myControl_);
    if (rc != RC_OK) {
        return RC_ERROR;
    }
    CAMERA_LOGI("UpdateSetting out, cameraID = %{public}s\n", cameraID.c_str());
    return RC_OK;
}

RetCode HosV4L2Dev::QuerySetting(const std::string& cameraID, unsigned int command, int* args)
{
    int32_t fd;
    int32_t value = 0;
    int rc = 0;
    CAMERA_LOGI("QuerySetting enter, cameraID = %{public}s\n", cameraID.c_str());
    if (args == nullptr) {
        CAMERA_LOGE("HosV4L2Dev::QuerySetting: args is NULL\n");
        return RC_ERROR;
    }

    if (myControl_ == nullptr) {
        myControl_ = std::make_shared<HosV4L2Control>();
        if (myControl_ == nullptr) {
            CAMERA_LOGE("HosV4L2Dev::QuerySetting: myControl_ make_shared is NULL\n");
            return RC_ERROR;
        }
    }

    fd = GetCurrentFd(cameraID);
    if (fd < 0) {
        CAMERA_LOGE("QuerySetting: GetCurrentFd error\n");
        return RC_ERROR;
    }

    rc = myControl_->V4L2GetCtrl(fd, command, value);
    if (rc != RC_OK) {
        return RC_ERROR;
    }

    *(reinterpret_cast<int32_t*>(args)) = value;
    CAMERA_LOGI("QuerySetting out, cameraID = %{public}s\n", cameraID.c_str());
    return RC_OK;
}

RetCode HosV4L2Dev::GetNumberCtrls(const std::string& cameraID, std::vector<DeviceControl>& control)
{
    int32_t fd;
    CAMERA_LOGI("GetNumberCtrls enter, cameraID = %{public}s\n", cameraID.c_str());
    if (myControl_ == nullptr) {
        myControl_ = std::make_shared<HosV4L2Control>();
        if (myControl_ == nullptr) {
            CAMERA_LOGE("HosV4L2Dev::GetNumberCtrls: myControl_ make_shared is NULL\n");
            return RC_ERROR;
        }
    }

    fd = GetCurrentFd(cameraID);
    if (fd < 0) {
        CAMERA_LOGE("GetNumberCtrls: GetCurrentFd error\n");
        return RC_ERROR;
    }

    return myControl_->V4L2GetCtrls(fd, control, control.size());
}

RetCode HosV4L2Dev::SetNumberCtrls(const std::string& cameraID, std::vector<DeviceControl>& control)
{
    int32_t fd;
    CAMERA_LOGI("SetNumberCtrls enter, cameraID = %{public}s\n", cameraID.c_str());
    if (myControl_ == nullptr) {
        myControl_ = std::make_shared<HosV4L2Control>();
        if (myControl_ == nullptr) {
            CAMERA_LOGE("HosV4L2Dev::SetNumberCtrls: myControl_ make_shared is NULL\n");
            return RC_ERROR;
        }
    }

    fd = GetCurrentFd(cameraID);
    if (fd < 0) {
        CAMERA_LOGE("SetNumberCtrls: GetCurrentFd error\n");
        return RC_ERROR;
    }

    return myControl_->V4L2SetCtrls(fd, control, control.size());
}

RetCode HosV4L2Dev::GetControls(const std::string& cameraID, std::vector<DeviceControl>& control)
{
    int fd, rc;
    CAMERA_LOGI("GetControls enter, cameraID = %{public}s\n", cameraID.c_str());
    if (myControl_ == nullptr) {
        myControl_ = std::make_shared<HosV4L2Control>();
        if (myControl_ == nullptr) {
            CAMERA_LOGE("HosV4L2Dev::GetControls: myControl_ make_shared is NULL\n");
            return RC_ERROR;
        }
    }

    fd = GetCurrentFd(cameraID);
    if (fd < 0) {
        CAMERA_LOGE("GetControls: GetCurrentFd error\n");
        return RC_ERROR;
    }

    rc = myControl_->V4L2GetControls(fd, control);
    if (rc == RC_ERROR) {
        CAMERA_LOGE("myControl_->V4L2GetControls fail\n");
        return RC_ERROR;
    }
    CAMERA_LOGI("GetControls out, cameraID = %{public}s\n", cameraID.c_str());
    return RC_OK;
}

RetCode HosV4L2Dev::GetFmtDescs(const std::string& cameraID, std::vector<DeviceFormat>& fmtDesc)
{
    int fd, rc;
    CAMERA_LOGI("GetFmtDescs enter, cameraID = %{public}s\n", cameraID.c_str());
    if (myFileFormat_ == nullptr) {
        CAMERA_LOGE("GetFmtDescs: myFileFormat_ == nullptr\n");
        return RC_ERROR;
    }

    fd = GetCurrentFd(cameraID);
    if (fd < 0) {
        CAMERA_LOGE("GetFmtDescs: GetCurrentFd error\n");
        return RC_ERROR;
    }

    rc = myFileFormat_->V4L2GetFmtDescs(fd, fmtDesc);
    if (rc == RC_ERROR) {
        CAMERA_LOGE("myFileFormat_->V4L2GetFmtDescs fail\n");
        return RC_ERROR;
    }
    CAMERA_LOGI("GetFmtDescs out, cameraID = %{public}s\n", cameraID.c_str());
    return RC_OK;
}

RetCode HosV4L2Dev::ConfigFps(const int fd, DeviceFormat& format, V4l2FmtCmd command)
{
    RetCode rc = RC_OK;
    CAMERA_LOGI("ConfigFps enter, fd = %{public}d\n", fd);
    if (myStreams_ == nullptr) {
        myStreams_ = std::make_shared<HosV4L2Streams>(bufferType_);
        if (myStreams_ == nullptr) {
            CAMERA_LOGE("error: ConfigSys: myStreams_ make_shared is nullptr\n");
            return RC_ERROR;
        }
    }

    if (command == CMD_V4L2_SET_FPS) {
        rc = myStreams_->V4L2StreamFPSSet(fd, format);
    } else {
        rc = myStreams_->V4L2StreamFPSGet(fd, format);
    }

    if (rc != RC_OK) {
        CAMERA_LOGE("ConfigFps CMD %d fail\n", command);
    }
    CAMERA_LOGI("ConfigFps out, fd = %{public}d\n", fd);
    return rc;
}

RetCode HosV4L2Dev::ConfigSys(const std::string& cameraID, V4l2FmtCmd command, DeviceFormat& format)
{
    int fd;
    RetCode rc = RC_OK;
    CAMERA_LOGI("ConfigSys enter, cameraID = %{public}s\n", cameraID.c_str());
    if (myFileFormat_ == nullptr) {
        CAMERA_LOGE("GetFmtDescs: ConfigSys == nullptr\n");
        return RC_ERROR;
    }

    fd = GetCurrentFd(cameraID);
    if (fd < 0) {
        CAMERA_LOGE("ConfigSys: GetCurrentFd error\n");
        return RC_ERROR;
    }

    switch (command) {
        case CMD_V4L2_GET_FORMAT:
            rc = myFileFormat_->V4L2GetFmt(fd, format);
            break;

        case CMD_V4L2_SET_FORMAT:
            rc = myFileFormat_->V4L2SetFmt(fd, format);
            break;

        case CMD_V4L2_GET_CROPCAP:
            rc = myFileFormat_->V4L2GetCropCap(fd, format);
            break;

        case CMD_V4L2_GET_CROP:
            rc = myFileFormat_->V4L2GetCrop(fd, format);
            break;

        case CMD_V4L2_SET_CROP:
            rc = myFileFormat_->V4L2SetCrop(fd, format);
            break;

        case CMD_V4L2_SET_FPS:
        case CMD_V4L2_GET_FPS:
            rc = ConfigFps(fd, format, command);
            break;

        default:
            CAMERA_LOGE("HosV4L2Dev::ConfigSys unknown command\n");
            break;
    }

    if (rc != RC_OK) {
        CAMERA_LOGE("ConfigSys CMD %d fail\n", command);
    }

    return rc;
}

RetCode HosV4L2Dev::SetV4L2DevCallback(BufCallback cb)
{
    if (cb == nullptr) {
        CAMERA_LOGE("HosV4L2Dev::SetCallback is null");
        return RC_ERROR;
    }
    if (myBuffers_ == nullptr) {
        CAMERA_LOGE("SetCallback myBuffers_ is NULL\n");
        return RC_ERROR;
    }

    myBuffers_->SetV4L2BuffersCallback(cb);

    return RC_OK;
}
RetCode HosV4L2Dev::Flush(const std::string& cameraID)
{
    int rc, fd;
    CAMERA_LOGI("Flush enter, cameraID = %{public}s\n", cameraID.c_str());
    fd = GetCurrentFd(cameraID);
    if (fd < 0) {
        CAMERA_LOGE("HosV4L2Dev::Flush: GetCurrentFd error\n");
        return RC_ERROR;
    }

    if (myBuffers_ == nullptr) {
        CAMERA_LOGE(" HosV4L2Dev::Flush myBuffers_ is NULL\n");
        return RC_ERROR;
    }

    rc = myBuffers_->Flush(fd);
    if (rc == RC_ERROR) {
        CAMERA_LOGE("HosV4L2Dev::Flush: error\n");
        return RC_ERROR;
    }
    CAMERA_LOGI("Flush out, cameraID = %{public}s\n", cameraID.c_str());
    return RC_OK;
}

void HosV4L2Dev::SetMemoryType(uint8_t &memType)
{
    CAMERA_LOGI("func[HosV4L2Dev::%{public}s] memType[%{public}d]", __func__, memType);
    if (memType == V4L2_MEMORY_MMAP) {
        memoryType_ = V4L2_MEMORY_MMAP;
    } else if (memType == V4L2_MEMORY_DMABUF) {
        memoryType_ = V4L2_MEMORY_DMABUF;
    }
}
} // namespace OHOS::Camera
