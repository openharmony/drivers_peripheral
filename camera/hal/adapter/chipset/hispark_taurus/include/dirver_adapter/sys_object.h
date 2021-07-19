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

#ifndef HOS_CAMERA_SYS_OBJECT_H
#define HOS_CAMERA_SYS_OBJECT_H

#include "ibuffer.h"
#include "mpi_adapter.h"
#include <functional>
#include <string>
#include <thread>
#include <list>
#include <mutex>
#include <map>

extern "C" {
#include "hal_sys.h"
#include "hal_vi.h"
#include "hal_comm.h"
}

namespace OHOS::Camera {
class SysObject {
public:
    SysObject();
    ~SysObject();
    void ConfigSys(std::vector<DeviceFormat>& format);
    RetCode StartSys();
    RetCode StopSys();
    void ViBindVpss(VI_PIPE viPipe, VI_CHN viChn, VPSS_GRP vpssGrp, VPSS_CHN vpssChn = 0);
    void ViUnBindVpss(VI_PIPE viPipe, VI_CHN viChn, VPSS_GRP vpssGrp, VPSS_CHN vpssChn = 0);
    void VpssBindVo(VPSS_GRP vpssGrp, VPSS_CHN vpssChn, VO_LAYER voLayer, VO_CHN voChn);
    void VpssUnBindVo(VPSS_GRP vpssGrp, VPSS_CHN vpssChn, VO_LAYER voLayer, VO_CHN voChn);
    void VpssBindVenc(VPSS_CHN vpssChn, VENC_CHN vencChn);
    void VpssUnBindVenc(VPSS_CHN vpssChn, VENC_CHN vencChn);
    void SetCallback(BufCallback cb);
    void SetDevStatusCallback(DeviceStatusCb cb);
    RetCode RequestBuffer(std::shared_ptr<FrameSpec> &buffer);
private:
    RetCode RequestVpssBuffer(std::shared_ptr<FrameSpec> &frameSpec);
    RetCode RequestVencBuffer(std::shared_ptr<FrameSpec> &frameSpec);
    RetCode CreateThread();
    RetCode ConfigureStream(std::shared_ptr<FrameSpec> &frameSpec);
    RetCode StreamAttachPort(const uint32_t poolId, const uint32_t bufSize, int32_t *portNum);
    RetCode StreamDetachPort();
    RetCode AddBufferToPool(std::shared_ptr<FrameSpec> &frameSpec);
    RetCode DelBufferFromPool();
    RetCode DestroyPool();
    RetCode DestroyProcResource();
    RetCode DestroyVencResource();
    RetCode SelectVpssPort(uint32_t bufSize);
    RetCode ReleaseProcBuffer();
    void SearchVencBuffer();
    void SearchBuffer();
private:
    VB_CONFIG_S pstVbConfig_;
    BufCallback dequeueBuffer_;
    DeviceStatusCb devStatusCb_;
    std::thread* searchThread_ = nullptr;
    std::thread* vencThread_ = nullptr;
    uint32_t threadFlag_;
    bool vencInitFlag_;
    uint32_t vencThreadFlag_;
    std::map<uint32_t, PoolSpec> poolMap_;
    std::list<std::shared_ptr<FrameSpec>> fSpecList_ = {};
    std::list<std::shared_ptr<FrameSpec>> fSpecVencList_ = {};
    std::list<VIDEO_FRAME_INFO_S> vFrameList_ = {};
    std::vector<uint32_t> blkId_;
    std::vector<uint32_t> poolId_;
    std::mutex lock_;
    int32_t vpssVencChn_ = 0;
    uint64_t vencFrameNum_ = 0;
};

struct SdkIncubator {
    SdkIncubator()
    {
        CameraSdkInit();
    }

    ~SdkIncubator()
    {
        CameraSdkExit();
    }
};

struct ThreadParam {
      SysObject* pThis;
      uint32_t timeout;
};

using ThreadParam = struct ThreadParam;
}

#endif // HOS_CAMERA_SYS_OBJECT_H

