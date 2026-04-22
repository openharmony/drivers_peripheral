/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#ifndef OHOS_HDI_SERIALS_V1_0_SERIAL_DEVICE_H
#define OHOS_HDI_SERIALS_V1_0_SERIAL_DEVICE_H

#include "v1_0/iserial_device.h"
#include <shared_mutex>
#include <atomic>
#include <string>
#include <vector>
#include <thread>
#include <memory>
#include <fcntl.h>
#include <termios.h>
#include <poll.h>
#include "v1_0/serial_types.h"
#include "v1_0/iserial_device_callback.h"
#include "serial_device_callback.h"

namespace OHOS {
namespace HDI {
namespace Serials {
namespace V1_0 {
class SerialDevice : public ISerialDevice {
public:
    explicit SerialDevice(std::string& portName, const sptr<ISerialDeviceCallback>& cb, const SerialConfig& config);
    virtual ~SerialDevice();

    int32_t StartRead() override;

    int32_t StopRead() override;

    int32_t Close() override;

    int32_t Write(const std::vector<uint8_t>& data, int32_t timeout, int32_t& bytesWritten) override;

    int32_t Flush() override;

    int32_t Drain() override;

    int32_t SendBrkSignal() override;

    int32_t SetRtsSignal(bool rts) override;

    int32_t GetCtsSignal(bool& cts) override;

    int32_t Open();

    int32_t NotifyDeviceOffline();

private:
    int32_t ConfigurePort();
    int32_t SetBaudRateInternal(struct termios& options);
    int32_t SetDataBitsInternal(struct termios& options);
    int32_t SetStopBitsInternal(struct termios& options);
    int32_t SetRtsCtsInternal(struct termios& options);
    int32_t SetXonXoffInternal(struct termios& options);
    int32_t SetParityInternal(struct termios& options);
    int32_t StopReadLocked();
    int32_t InitPipes();
    void ClosePipes();
    void ReadThread(int32_t timeout);
    int32_t PollForRead(struct pollfd* fds, int32_t timeout);
    bool HandleReadEvent(struct pollfd* fds, std::vector<int8_t>& buffer, int32_t& bytesRead);
    int32_t PollForWrite(struct pollfd* fds, int32_t timeout);
    int32_t DoWriteLoop(const uint8_t* data, size_t size, int32_t timeout, size_t& written);

    std::unique_ptr<SerialDeviceCallback> cb_;
    std::string portName_;
    int32_t fd_;
    SerialConfig currentConfig_;
    std::atomic<bool> isOpen_;
    std::atomic<bool> startRead_;
    int stopPipe_[2];
    int closePipe_[2];
    mutable std::shared_mutex mutex_;
    std::thread readThread_;
};
} // V1_0
} // Serials
} // HDI
} // OHOS

#endif // OHOS_HDI_SERIALS_V1_0_SERIAL_DEVICE_H
