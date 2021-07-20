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

#ifndef HOS_CAMERA_VPSS_OBJECT_H
#define HOS_CAMERA_VPSS_OBJECT_H

#include "mpi_adapter.h"
extern "C" {
#include "hal_vi.h"
#include "hal_proc.h"
}

#define INIT_PARAM_KEY_MAX_LEN 128


namespace OHOS::Camera {
class VpssObject {
public:
    void Init();
    VpssObject();
    ~VpssObject();
    void ConfigVpss(std::vector<DeviceFormat>& format);
    RetCode StartVpss();
    RetCode StopVpss();

private:
    CAMERA_VI_CONFIG_S viConfig_;
    HI_BOOL chnEnable_[VPSS_MAX_PHY_CHN_NUM] = {};
    VPSS_CHN_ATTR_S vpssChnAttr_[VPSS_MAX_PHY_CHN_NUM] = {};
    VPSS_GRP_ATTR_S vpssGrpAttr_;
};
}
#endif // HOS_CAMERA_VPSS_OBJECT_H

