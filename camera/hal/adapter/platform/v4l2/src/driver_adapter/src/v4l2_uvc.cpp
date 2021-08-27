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

#include "v4l2_uvc.h"
#include "securec.h"
#include "v4l2_control.h"
#include "v4l2_fileformat.h"
#include "v4l2_dev.h"

namespace OHOS::Camera {
HosV4L2UVC::HosV4L2UVC() {}
HosV4L2UVC::~HosV4L2UVC() {}

void HosV4L2UVC::V4L2UvcSearchCapability(const std::string devName, const std::string v4l2Device, bool inOut)
{
    if (devName.length() == 0 || v4l2Device.length() == 0) {
        CAMERA_LOGE("UVC:V4L2UvcSearchCapability devName or v4l2Device is null");
    }

    std::vector<DeviceControl>().swap(control_);
    std::vector<DeviceFormat>().swap(format_);

    if (inOut) {
        char name[16] = {0};

        sprintf_s(name, sizeof(name), "%s%s", "/dev/", v4l2Device.c_str());
        int fd = open(name, O_RDWR | O_NONBLOCK, 0);
        if (fd < 0) {
            CAMERA_LOGE("UVC:V4L2UvcSearchCapability open %s name %s error\n", v4l2Device.c_str(), devName.c_str());
        } else {
            std::shared_ptr<HosFileFormat> fileFormat = nullptr;
            fileFormat = std::make_shared<HosFileFormat>();
            if (fileFormat == nullptr) {
                CAMERA_LOGE("UVC:V4L2UvcMatchDev fileFormat make_shared is NULL\n");
            } else {
                fileFormat->V4L2GetFmtDescs(fd, format_);
            }

            std::shared_ptr<HosV4L2Control> control = nullptr;
            control = std::make_shared<HosV4L2Control>();
            if (control == nullptr) {
                CAMERA_LOGE("UVC:V4L2UvcMatchDev control make_shared is NULL\n");
            } else {
                control->V4L2GetControls(fd, control_);
            }

            close(fd);
        }
    }
}

void HosV4L2UVC::V4L2UvcMatchDev(const std::string name, const std::string v4l2Device, bool inOut)
{
    std::pair<std::map<std::string, std::string>::iterator, bool> iter;
    constexpr uint32_t nameSize = 16;
    int i = 0;
    char devName[nameSize] = {0};

    CAMERA_LOGD("UVC:V4L2UvcMatchDev name %s v4l2Device %s inOut = %d\n",
        name.c_str(), v4l2Device.c_str(), inOut);
    sprintf_s(devName, sizeof(devName), "%s", name.c_str());
    if (inOut) {
        {
            std::lock_guard<std::mutex> l(HosV4L2Dev::deviceFdLock_);
            iter = HosV4L2Dev::deviceMatch.insert(std::make_pair(std::string(devName), v4l2Device));
        }
        if (!iter.second) {
            for (i = 1; i < MAXUVCNODE; i++) {
                sprintf_s(devName, sizeof(devName), "%s%d", devName, i);
                {
                    std::lock_guard<std::mutex> l(HosV4L2Dev::deviceFdLock_);
                    iter = HosV4L2Dev::deviceMatch.insert(std::make_pair(std::string(devName), v4l2Device));
                }
                if (iter.second) {
                    CAMERA_LOGD("UVC: V4L2UvcMatchDev::deviceMatch.insert: %s devName %s i %d\n",
                        v4l2Device.c_str(), devName, i);
                    break;
                }
            }

        }
    }else {
        CAMERA_LOGD("UVC: HosV4L2Dev::deviceMatch.erase: %s devName %s\n",
            v4l2Device.c_str(), devName);
        std::lock_guard<std::mutex> l(HosV4L2Dev::deviceFdLock_);
        HosV4L2Dev::deviceMatch.erase(std::string(devName));
    }

    V4L2UvcSearchCapability(std::string(devName), v4l2Device, inOut);

    uvcCallbackFun_(std::string(devName), control_, format_, inOut);
}

RetCode HosV4L2UVC::V4L2UvcGetCap(const std::string v4l2Device, struct v4l2_capability& cap)
{
    int fd, rc;
    char devName[16] = {0};

    sprintf_s(devName, sizeof(devName), "%s%s", "/dev/", v4l2Device.c_str());
    fd = open(devName, O_RDWR | O_NONBLOCK, 0);
    if (fd < 0) {
        CAMERA_LOGE("UVC:ERROR opening V4L2 interface for %s\n", v4l2Device.c_str());
        return RC_ERROR;
    }

    rc = ioctl(fd, VIDIOC_QUERYCAP, &cap);
    if (rc < 0) {
        CAMERA_LOGE("UVC:%s V4L2EnmeDevices VIDIOC_QUERYCAP erro\n", v4l2Device.c_str());
        close(fd);
        return RC_ERROR;
    }
    close(fd);

    return RC_OK;
}

RetCode HosV4L2UVC::V4L2UvcEnmeDevices()
{
    return RC_OK;
}


const char* HosV4L2UVC::V4L2GetUsbValue(const char* key, const char* str, int len)
{
    if (key == nullptr || str == nullptr || len <= 0 || strlen(key) > len) {
        return nullptr;
    }

    const char* pos = strstr(str, key);
    if (pos == nullptr) {
        return nullptr;
    }

    if (pos + strlen(key) - str > len) {
        return nullptr;
    }

    return pos + strlen(key);
}

void HosV4L2UVC::V4L2GetUsbString(std::string& action, std::string& subsystem,
    std::string& devnode, char* buf, unsigned int len)
{
    int lineLen;
    int pos = 0;
    const char* retVal;

    CAMERA_LOGD("UVC:V4L2GetUsbString enter\n");

    lineLen = strlen(buf);
    while (pos + lineLen < len && lineLen) {
        if (action == "") {
            retVal = V4L2GetUsbValue("ACTION=", buf + pos, lineLen);
            if (retVal == nullptr) {
                action = "";
            } else {
                action = std::string(retVal);
                CAMERA_LOGD("UVC:V4L2GetUsbString action %s\n", action.c_str());
            }
        }

        if (subsystem == "") {
            retVal = V4L2GetUsbValue("SUBSYSTEM=", buf + pos, lineLen);
            if (retVal == nullptr) {
                subsystem = "";
            } else {
                subsystem = std::string(retVal);
                CAMERA_LOGD("UVC:V4L2GetUsbString subsystem %s\n", subsystem.c_str());
            }
        }

        if (devnode == "") {
            retVal = V4L2GetUsbValue("DEVNAME=", buf + pos, lineLen);
            if (retVal == nullptr) {
                devnode = "";
            } else {
                devnode = std::string(retVal);
                CAMERA_LOGD("UVC:V4L2GetUsbString devnode %s\n", devnode.c_str());
            }
        }

        pos += lineLen + 1;
        lineLen = strlen(buf + pos);
    }

    CAMERA_LOGD("UVC:V4L2GetUsbString exit\n");
}

void HosV4L2UVC::loopUvcDevice()
{
    fd_set fds;
    int rc;

    CAMERA_LOGD("UVC:loopUVCDevice fd = %d getuid() = %d\n", uDevFd_, getuid());
    rc = V4L2UvcEnmeDevices();
    if (rc == RC_ERROR) {
        CAMERA_LOGE("UVC:loopUVCDevice V4L2EnmeDevices error\n");
        return;
    }

    FD_ZERO(&fds);
    FD_SET(uDevFd_, &fds);
    FD_SET(eventFd_, &fds);
    while (uvcDetectEnable_) {
        rc = select(((uDevFd_ > eventFd_) ? uDevFd_ : eventFd_) + 1, &fds, &fds, NULL, NULL);
        if (rc > 0 && FD_ISSET(uDevFd_, &fds)) {
            sleep(1);
            constexpr uint32_t buffSize = 4096;
            char buf[buffSize] = {};
            unsigned int len = recv(uDevFd_, buf, sizeof(buf), 0);

            if (len > 0 && (strstr(buf, "video4linux") != nullptr)) {
                std::string action = "";
                std::string subsystem = "";
                std::string devnode = "";
                V4L2GetUsbString(action, subsystem, devnode, buf, len);
                if (subsystem == "video4linux") {
                    CAMERA_LOGD("UVC:ACTION = %s, SUBSYSTEM = %s, DEVNAME = %s\n", action.c_str(), subsystem.c_str(), devnode.c_str());

                    if (action == "remove") {
                        for (auto &itr : HosV4L2Dev::deviceMatch) {
                            if (itr.second == devnode) {
                                CAMERA_LOGD("UVC:loop HosV4L2Dev::deviceMatch %s\n", action.c_str());
                                V4L2UvcMatchDev(itr.first, devnode, false);
                                break;
                            }
                        }
                    } else {
                        struct v4l2_capability cap = {};
                        rc = V4L2UvcGetCap(devnode.c_str(), cap);
                        if (rc == RC_ERROR) {
                            CAMERA_LOGE("UVC:loop V4L2UvcGetCap error rc %d\n", rc);
                            continue;
                        }

                        CAMERA_LOGD("UVC:loop HosV4L2Dev::deviceMatch %s\n", action.c_str());
                        V4L2UvcMatchDev(std::string((char*)cap.driver), devnode, true);
                    }
                }
            }
        } else
            CAMERA_LOGD("UVC:No Device from udev_monitor_receive_device() or exit uvcDetectEnable_ = %d\n",
                uvcDetectEnable_);
    }
}

void HosV4L2UVC::V4L2UvcDetectUnInit()
{
    int rc;
    constexpr uint32_t delayTime = 300000;

    uvcDetectEnable_ = 0;

    CAMERA_LOGD("UVC:loop V4L2UvcDetectUnInit\n");

    uint64_t one = 1;
    rc = write(eventFd_, &one, sizeof(one));
    if (rc < 0) {
        usleep(delayTime);
        rc = write(eventFd_, &one, sizeof(one));
    }

    uvcDetectThread_->join();
    close(uDevFd_);
    close(eventFd_);

    delete uvcDetectThread_;
    uvcDetectThread_ = nullptr;
}

RetCode HosV4L2UVC::V4L2UvcDetectInit(UvcCallback cb)
{
    int rc;
    struct sockaddr_nl nls;

    CAMERA_LOGD("UVC:V4L2Detect enter\n");

    if (cb == nullptr || uvcDetectEnable_) {
        CAMERA_LOGE("UVC:V4L2Detect is on or UvcCallback is NULL\n");
        return RC_ERROR;
    }
    //set callback
    uvcCallbackFun_ = cb;

    uDevFd_ = socket(PF_NETLINK, SOCK_RAW, NETLINK_KOBJECT_UEVENT);
    if (uDevFd_ < 0) {
        CAMERA_LOGE("UVC:V4L2Detect socket() error\n");
        return RC_ERROR;
    }

    memset(&nls, 0, sizeof(nls));
    nls.nl_family = AF_NETLINK;
    nls.nl_pid = getpid();
    nls.nl_groups = 1;
    rc = bind(uDevFd_, (struct sockaddr *)&nls, sizeof(nls));
    if (rc < 0) {
        CAMERA_LOGE("UVC:V4L2Detect bind() error\n");
        goto error;
    }

    eventFd_ = eventfd(0, 0);
    if (eventFd_ < 0) {
        CAMERA_LOGE("UVC:V4L2Detect eventfd error\n");
        goto error;
    }

    uvcDetectEnable_ = 1;
    uvcDetectThread_ = new (std::nothrow) std::thread(&HosV4L2UVC::loopUvcDevice, this);
    if (uvcDetectThread_ == nullptr) {
        uvcDetectEnable_ = 0;
        CAMERA_LOGE("UVC:V4L2Detect creat loopUVCDevice thread error\n");
        goto error1;
    }

    return RC_OK;

error1:
    close (eventFd_);
    uvcCallbackFun_ = nullptr;
error:
    close (uDevFd_);

    return RC_ERROR;
}
} // namespace OHOS::Camera
