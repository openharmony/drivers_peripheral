/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#undef LOG_DOMAIN
#define LOG_DOMAIN 0xD002BD0
#include "midi_interface_impl.h"
#include "midi_driver_controller.h"
#include <hdf_base.h>
#include <hdf_log.h>


#define HDF_LOG_TAG midi_interface_impl

namespace OHOS {
namespace HDI {
namespace Midi {
namespace V1_0 {
extern "C" IMidiInterface *MidiInterfaceImplGetInstance(void)
{
    return new (std::nothrow) MidiInterfaceImpl();
}

extern "C" void MidiInterfaceImplRelease(void *ptr)
{
    delete (MidiInterfaceImpl *)ptr;
}

int32_t MidiInterfaceImpl::GetDeviceList(std::vector<MidiDeviceInfo> &deviceList)
{
    HDF_LOGI("%{public}s: Enter", __func__);
    // TODO: 实现获取 ALSA 卡列表并过滤 MIDI 设备的逻辑 [cite: 12]
    return MidiDriverController::GetInstance()->GetDeviceList(deviceList);
}

int32_t MidiInterfaceImpl::OpenDevice(int64_t deviceId)
{
    HDF_LOGI("%{public}s: Enter, deviceId=%{public}" PRId64, __func__, deviceId);
    // TODO: 初始化设备资源
    return MidiDriverController::GetInstance()->OpenDevice(deviceId);
}

int32_t MidiInterfaceImpl::CloseDevice(int64_t deviceId)
{
    HDF_LOGI("%{public}s: Enter, deviceId=%{public}" PRId64, __func__, deviceId);
    // TODO: 释放设备资源
    return MidiDriverController::GetInstance()->CloseDevice(deviceId);
}

int32_t MidiInterfaceImpl::OpenInputPort(int64_t deviceId, uint32_t portId, const sptr<IMidiCallback> &dataCallback)
{
    HDF_LOGI("%{public}s: Enter, deviceId=%{public}" PRId64 ", portId=%{public}u", __func__, deviceId, portId);
    if (dataCallback == nullptr) {
        HDF_LOGE("%{public}s: dataCallback is null", __func__);
        return HDF_ERR_INVALID_PARAM;
    }
    // TODO: 启动监听线程并注册回调
    return MidiDriverController::GetInstance()->OpenInputPort(deviceId, portId, dataCallback);
}

int32_t MidiInterfaceImpl::CloseInputPort(int64_t deviceId, uint32_t portId)
{
    HDF_LOGI("%{public}s: Enter, deviceId=%{public}" PRId64 ", portId=%{public}u", __func__, deviceId, portId);
    // TODO: 停止监听任务
    return MidiDriverController::GetInstance()->CloseInputPort(deviceId, portId);
}

int32_t MidiInterfaceImpl::OpenOutputPort(int64_t deviceId, uint32_t portId)
{
    HDF_LOGI("%{public}s: Enter, deviceId=%{public}" PRId64 ", portId=%{public}u", __func__, deviceId, portId);
    // TODO: 准备端口发送数据
    return MidiDriverController::GetInstance()->OpenOutputPort(deviceId, portId);
}

int32_t MidiInterfaceImpl::CloseOutputPort(int64_t deviceId, uint32_t portId)
{
    HDF_LOGI("%{public}s: Enter, deviceId=%{public}" PRId64 ", portId=%{public}u", __func__, deviceId, portId);
    // TODO: 释放输出端口资源
    return MidiDriverController::GetInstance()->CloseOutputPort(deviceId, portId);
}

int32_t MidiInterfaceImpl::SendMidiMessages(int64_t deviceId, uint32_t portId, const std::vector<MidiMessage> &messages)
{
    // 避免在数据发送路径上打印过多日志，通常建议使用 debug 级别或仅在错误时打印
    // HDF_LOGD("%{public}s: Enter, count=%{public}zu", __func__, messages.size());

    // TODO: 将 UMP 消息转换为字节流（如果需要）并写入硬件驱动 [cite: 52]
    return MidiDriverController::GetInstance()->SendMidiMessages(deviceId, portId, messages);
}
} // namespace V1_0
} // namespace Midi
} // namespace HDI
} // namespace OHOS