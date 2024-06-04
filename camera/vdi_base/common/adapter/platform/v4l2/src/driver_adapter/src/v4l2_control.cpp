/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "v4l2_control.h"

namespace OHOS::Camera {
HosV4L2Control::HosV4L2Control() {}
HosV4L2Control::~HosV4L2Control() {}

void HosV4L2Control::V4L2VidiocSCtrl (int fd, int ret, struct v4l2_ext_control* cList, int count)
{
    if (ret) {
        CAMERA_LOGE("HosV4L2Control::VIDIOC_S_EXT_CTRLS set failed try to VIDIOC_S_CTRL\n");
        struct v4l2_control ctrl;
        for (int i = 0; count > 0; i++, count--) {
            ctrl.id = cList[i].id;
            ctrl.value = cList[i].value;
            ret = ioctl(fd, VIDIOC_S_CTRL, &ctrl);
            if (ret) {
                CAMERA_LOGE("HosV4L2Control::V4L2SetCtrls VIDIOC_S_CTRL error i = %{public}d\n", i);
                continue;
            }
        }
    }
}

RetCode HosV4L2Control::V4L2SetCtrls (int fd, std::vector<DeviceControl>& control, const int numControls)
{
    int ret;
    int count = 0;
    CAMERA_LOGI("HosV4L2Control::V4L2SetCtrls in fd %{public}d\n", fd);
    if (numControls != static_cast<int>(control.size())) {
        CAMERA_LOGE("HosV4L2Control::V4L2SetCtrls numControls != control.size()\n");
        return RC_ERROR;
    }

    struct v4l2_ext_control cList[numControls];
    for (auto itr = control.begin(); itr != control.end(); itr++) {
        if (itr->flags & V4L2_CTRL_FLAG_READ_ONLY) {
            continue;
        }

        if (count < numControls) {
            cList[count].value = itr->value;
            count++;
        }
        auto itrNext = itr + 1;
        if (itrNext == control.end() || itr->ctrl_class != itrNext->ctrl_class) {
            struct v4l2_ext_controls ctrls = {};
            ctrls.ctrl_class = itr->ctrl_class;
            ctrls.count = count;
            ctrls.controls = cList;
            ret = ioctl(fd, VIDIOC_S_EXT_CTRLS, &ctrls);
            
            V4L2VidiocSCtrl(fd, ret, cList, count);
            count = 0;
        }
    }
    CAMERA_LOGI("HosV4L2Control::V4L2SetCtrls out fd %{public}d\n", fd);
    return RC_OK;
}

void HosV4L2Control::V4L2VidiocGExtCtrls (int fd, int ret, int &count,
    v4l2_ext_control *cList, std::vector<DeviceControl>& control)
{
    auto iter = control.begin();
    if (ret) {
        CAMERA_LOGE("HosV4L2Control::VIDIOC_G_EXT_CTRLS set failed try to VIDIOC_S_CTRL\n");
        struct v4l2_control ctrl;
        for (int i = 0; count > 0; i++, count--) {
            ctrl.id = cList[i].id;
            ret = ioctl(fd, VIDIOC_G_CTRL, &ctrl);
            if (ret) {
                continue;
            }

            iter->value = ctrl.value;
            iter++;
        }
    } else {
        for (int i = 0; count > 0; i++, count--) {
            iter->value = cList[i].value;
            iter++;
        }
    }
}

RetCode HosV4L2Control::V4L2GetCtrls (int fd, std::vector<DeviceControl>& control, const int numControls)
{
    int ret;
    int count = 0;
    CAMERA_LOGI("HosV4L2Control::V4L2GetCtrls in fd %{public}d\n", fd);
    if (numControls != static_cast<int>(control.size())) {
        CAMERA_LOGE("HosV4L2Control::V4L2GetCtrls numControls != control.size()\n");
        return RC_ERROR;
    }

    struct v4l2_ext_control cList[numControls];
    for (auto itr = control.begin(); itr != control.end(); itr++) {
        if (itr->flags & V4L2_CTRL_FLAG_WRITE_ONLY) {
            continue;
        }
        if (count < numControls) {
            cList[count].id = itr->id;
            count++;
        }

        auto itrNext = itr + 1;
        if (itrNext == control.end() || itr->ctrl_class != itrNext->ctrl_class) {
            struct v4l2_ext_controls ctrls = {};
            ctrls.ctrl_class = itr->ctrl_class;
            ctrls.count = count;
            ctrls.controls = cList;
            ret = ioctl(fd, VIDIOC_G_EXT_CTRLS, &ctrls);
            V4L2VidiocGExtCtrls(fd, ret, count, cList, control);

            count = 0;
        }
    }
    CAMERA_LOGI("HosV4L2Control::V4L2GetCtrls out fd %{public}d\n", fd);
    return RC_OK;
}

RetCode HosV4L2Control::V4L2GetCtrl(int fd, unsigned int id, int& value)
{
    CAMERA_LOGD("HosV4L2Control::V4L2GetCtrl in fd %{public}d\n", fd);
    int rc = 0;
    struct v4l2_control ctrl;

    ctrl.id = id;

    rc = ioctl(fd, VIDIOC_G_CTRL, &ctrl);
    if (rc < 0) {
        CAMERA_LOGE("HosV4L2Control::V4L2GetCtrl error rc = %{public}d", rc);
        return RC_ERROR;
    }

    value = ctrl.value;
    CAMERA_LOGD("HosV4L2Control::V4L2GetCtrl out fd %{public}d\n", fd);
    return RC_OK;
}

RetCode HosV4L2Control::V4L2SetCtrl(int fd, unsigned int id, int value)
{
    struct v4l2_control ctrl;
    int rc;

    CAMERA_LOGI("V4L2SetCtrl in fd = %{public}d, id = %{public}d, value = %{public}d\n", fd, id, value);

    ctrl.id = id;
    ctrl.value = value;

    rc = ioctl(fd, VIDIOC_S_CTRL, &ctrl);
    if (rc < 0) {
        CAMERA_LOGE("HosV4L2Control::V4L2SetCtrl error rc = %{public}d", rc);
        return RC_ERROR;
    }
    CAMERA_LOGI("V4L2SetCtrl out fd = %{public}d, id = %{public}d, value = %{public}d\n", fd, id, value);
    return RC_OK;
}

int HosV4L2Control::ExtControl(int fd, struct v4l2_queryctrl *ctrl)
{
    int ret = 0;
    CAMERA_LOGD("ExtControl in fd = %{public}d\n", fd);
    if (ctrl == nullptr) {
        CAMERA_LOGE("HosV4L2Control::ExtControl ctrl == nullptr");
        return -1;
    }

    ctrl->id |= V4L2_CTRL_FLAG_NEXT_CTRL;
    ret = ioctl(fd, VIDIOC_QUERYCTRL, ctrl);
    if (ret < 0) {
        CAMERA_LOGI("ExtControl out fd = %{public}d, ret = %{public}d\n", fd, ret);
    }
    return ret;
}

void HosV4L2Control::V4L2SetValue(int fd, std::vector<DeviceControl>& control,
    DeviceControl& ctrl, v4l2_queryctrl& qCtrl)
{
    CAMERA_LOGD("V4L2SetValue in fd = %{public}d\n", fd);
    int value, rc;

    ctrl.id = qCtrl.id;
    ctrl.ctrl_class = V4L2_CTRL_ID2CLASS(qCtrl.id);
    ctrl.type = qCtrl.type;
    ctrl.minimum = qCtrl.minimum;
    ctrl.maximum = qCtrl.maximum;
    ctrl.step = qCtrl.step;
    ctrl.default_value = qCtrl.default_value;
    ctrl.flags = qCtrl.flags;
    ctrl.name = std::string(reinterpret_cast<char*>(qCtrl.name));

    if (qCtrl.type == V4L2_CTRL_TYPE_CTRL_CLASS) {
        CAMERA_LOGD("%{public}s-14s\n", qCtrl.name);
        control.push_back(ctrl);
        return;
    }

    rc = V4L2GetCtrl(fd, qCtrl.id, value);
    if (rc != RC_ERROR) {
        ctrl.value = value;
        CAMERA_LOGD("%{public}s-14s : id=%{public}x-08x, type=%{public}d, minimum=%{public}d, maximum=%{public}d\n"
            "\t\t value = %{public}d, step=%{public}d, default_value=%{public}d\n",
            qCtrl.name, qCtrl.id, qCtrl.type, qCtrl.minimum, qCtrl.maximum,
            value, qCtrl.step, qCtrl.default_value);
    }
    CAMERA_LOGD("V4L2SetValue out fd = %{public}d\n", fd);
}

void HosV4L2Control::V4L2EnumExtControl(int fd, v4l2_queryctrl &qCtrl, DeviceControl &ctrl)
{
    int rc;
    if (qCtrl.type == V4L2_CTRL_TYPE_MENU) {
        struct v4l2_querymenu menu = {};
        V4l2Menu menuTemp = {};
        for (menu.index = static_cast<uint32_t>(qCtrl.minimum);
                menu.index <= static_cast<uint32_t>(qCtrl.maximum);
                menu.index++) {
            menu.id = qCtrl.id;
            rc = ioctl(fd, VIDIOC_QUERYMENU, &menu);
            if (rc < 0) {
                continue;
            }
            CAMERA_LOGD("\t V4L2EnumExtControls %{public}d : %{public}s\n", menu.index, menu.name);
            menuTemp.index = menu.index;
            menuTemp.id = menu.id;
            menuTemp.value = menu.value;
            menuTemp.name = std::string(reinterpret_cast<char*>(menu.name));
            ctrl.menu.push_back(menuTemp);
        }
    }
}

void HosV4L2Control::V4L2EnumExtControls(int fd, std::vector<DeviceControl>& control)
{
    CAMERA_LOGI("V4L2EnumExtControls in fd = %{public}d\n", fd);
    struct v4l2_queryctrl qCtrl = {};
    DeviceControl ctrl = {};

    qCtrl.id |= V4L2_CTRL_FLAG_NEXT_CTRL;
    while (!ExtControl(fd, &qCtrl)) {
        if (qCtrl.flags & V4L2_CTRL_FLAG_DISABLED) {
            CAMERA_LOGI("V4L2ENUMExtControls flags  V4L2_CTRL_FLAG_DISABLED\n");
            continue;
        }

        V4L2SetValue(fd, control, ctrl, qCtrl);

        V4L2EnumExtControl(fd, qCtrl, ctrl);
        // Need fix: ctrl menu will keep old menu. Need clear ctrl every convert
        control.push_back(ctrl);
    }
    CAMERA_LOGI("V4L2EnumExtControls out fd = %{public}d\n", fd);
}

int HosV4L2Control::V4L2GetControl(int fd, std::vector<DeviceControl>& control, unsigned int id)
{
    CAMERA_LOGI("V4L2GetControl in fd = %{public}d\n", fd);
    struct v4l2_queryctrl queryCtrl = {};
    DeviceControl ctrl = {};
    int rc;

    queryCtrl.id = id;
    rc = ioctl(fd, VIDIOC_QUERYCTRL, &queryCtrl);
    if (rc < 0) {
        CAMERA_LOGE("V4L2GetControl ioctl error rc %{public}d\n", rc);
        return RC_ERROR;
    }

    if (queryCtrl.flags & V4L2_CTRL_FLAG_DISABLED) {
        CAMERA_LOGI("V4L2ENUMExtControls flags  V4L2_CTRL_FLAG_DISABLED\n");
        return RC_OK;
    }

    V4L2SetValue(fd, control, ctrl, queryCtrl);

    if (queryCtrl.type == V4L2_CTRL_TYPE_MENU) {
        struct v4l2_querymenu menu = {};
        V4l2Menu mTemp = {};

        for (menu.index = static_cast<uint32_t>(queryCtrl.minimum);
                menu.index <= static_cast<uint32_t>(queryCtrl.maximum);
                menu.index++) {
            menu.id = queryCtrl.id;
            rc = ioctl(fd, VIDIOC_QUERYMENU, &menu);
            if (rc < 0) {
                continue;
            }
            CAMERA_LOGD("\t %d : %s\n", menu.index, menu.name);
            mTemp.index = menu.index;
            mTemp.id = menu.id;
            mTemp.value = menu.value;
            mTemp.name = std::string(reinterpret_cast<char*>(menu.name));
            ctrl.menu.push_back(mTemp);
        }
    }

    control.push_back(ctrl);
    CAMERA_LOGI("V4L2GetControl out fd = %{public}d\n", fd);
    return RC_OK;
}

void HosV4L2Control::V4L2EnumControls(int fd, std::vector<DeviceControl>& control)
{
    CAMERA_LOGI("V4L2EnumControls in fd = %{public}d\n", fd);
    int rc;
    constexpr uint32_t max = V4L2_CID_PRIVATE_BASE + 100;

    for (unsigned int id = V4L2_CID_BASE; id < V4L2_CID_LASTP1; id++) {
        rc = V4L2GetControl(fd, control, id);
            if (rc == RC_ERROR)
                break;
    }

    for (unsigned int id = V4L2_CID_PRIVATE_BASE; id < max; id++) {
        rc = V4L2GetControl(fd, control, id);
            if (rc == RC_ERROR)
                break;
    }
    CAMERA_LOGI("V4L2EnumControls out fd = %{public}d\n", fd);
}

RetCode HosV4L2Control::V4L2GetControls(int fd, std::vector<DeviceControl>& control)
{
    CAMERA_LOGI("V4L2GetControls out fd = %{public}d\n", fd);
    int rc;
    struct v4l2_queryctrl qCtrl = {};

    std::vector<DeviceControl>().swap(control);

    if (fd < 0) {
        CAMERA_LOGE("V4L2EnumExtControls fd error\n");
        return RC_ERROR;
    }

    qCtrl.id |= V4L2_CTRL_FLAG_NEXT_CTRL;
    rc = ExtControl(fd, &qCtrl);
    if (rc < 0) {
        CAMERA_LOGE("V4L2GetControls no support V4L2_CTRL_FLAG_NEXT_CTRL\n");
        V4L2EnumControls(fd, control);
    } else {
        CAMERA_LOGE("V4L2GetControls support V4L2_CTRL_FLAG_NEXT_CTRL\n");
        V4L2EnumExtControls(fd, control);
    }
    CAMERA_LOGI("V4L2GetControls in fd = %{public}d\n", fd);
    return RC_OK;
}
} // namespace OHOS::Camera
