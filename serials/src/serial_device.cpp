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

#include "serial_device.h"
#include <hdf_base.h>
#include <hdf_log.h>
#include <fcntl.h>
#include <unistd.h>
#include <cstring>
#include <sys/ioctl.h>
#include <sys/file.h>
#include "securec.h"
#include "serial_consts.h"
#include "hdf_trace.h"

#undef LOG_TAG
#define LOG_TAG "SERIAL_IMPL"
#undef LOG_DOMAIN
#define LOG_DOMAIN 0xD002519
#ifndef BOTHER
#define BOTHER 0010000
#endif
#ifndef CBAUD
#define CBAUD 001017
#endif

namespace OHOS {
namespace HDI {
namespace Serials {
namespace V1_0 {

SerialDevice::SerialDevice(std::string& portName, const sptr<ISerialDeviceCallback>& cb, const SerialConfig& config)
    : portName_(portName), fd_(INVALID_FD), currentConfig_(config), isOpen_(false), startRead_(false),
      stopPipe_{INVALID_FD, INVALID_FD}, closePipe_{INVALID_FD, INVALID_FD}
{
    cb_ = std::make_unique<SerialDeviceCallback>(cb);
    HDF_LOGI("path=%{public}s!", portName_.c_str());
}

SerialDevice::~SerialDevice()
{
    HDF_LOGI("%{public}s called!", __func__);
    Close();
}

int32_t SerialDevice::Open()
{
    std::unique_lock lock(mutex_);
    if (isOpen_) {
        HDF_LOGW("device already open.%{public}s", portName_.c_str());
        return HDF_ERR_DEVICE_BUSY;
    }
    HdfTrace openTrace("Serial::Open");
    fd_ = open(portName_.c_str(), O_RDWR | O_NOCTTY | O_NDELAY);
    if (fd_ < 0) {
        if (errno == ENODEV) {
            HDF_LOGW("device not exist.%{public}s", portName_.c_str());
            return HDF_DEV_ERR_NO_DEVICE;
        } else {
            HDF_LOGE("open failed.%{public}s - errno=%{public}d (%{public}s)\n",
                portName_.c_str(), errno, strerror(errno));
        }

        return HDF_ERR_IO;
    }
    fdsan_exchange_owner_tag(fd_, 0, fdsan_create_owner_tag(FDSAN_OWNER_TYPE_FILE, LOG_DOMAIN));
    if (flock(fd_, LOCK_EX | LOCK_NB) < 0) {
        HDF_LOGE("lock failed.%{public}s-err=%{public}d (%{public}s)\n", portName_.c_str(), errno, strerror(errno));
        fdsan_close_with_tag(fd_, fdsan_create_owner_tag(FDSAN_OWNER_TYPE_FILE, LOG_DOMAIN));
        fd_ = INVALID_FD;
        return HDF_ERR_IO;
    }
    int ret = HDF_SUCCESS;
    if ((ret = ConfigurePort()) != HDF_SUCCESS) {
        fdsan_close_with_tag(fd_, fdsan_create_owner_tag(FDSAN_OWNER_TYPE_FILE, LOG_DOMAIN));
        fd_ = INVALID_FD;
        return ret;
    }
    if (InitPipes() != HDF_SUCCESS) {
        fdsan_close_with_tag(fd_, fdsan_create_owner_tag(FDSAN_OWNER_TYPE_FILE, LOG_DOMAIN));
        fd_ = INVALID_FD;
        return HDF_ERR_IO;
    }
    isOpen_ = true;
    HDF_LOGI("Open %{public}s success! fd:%{public}d", portName_.c_str(), fd_);
    return HDF_SUCCESS;
}

int32_t SerialDevice::StartRead()
{
    HDF_LOGI("StartRead %{public}s! fd:%{public}d", portName_.c_str(), fd_);
    std::shared_lock lock(mutex_);
    if (!isOpen_.load()) {
        HDF_LOGE("%{public}s, device not open!", __func__);
        return HDF_ERR_INVALID_OBJECT;
    }
    if (startRead_.load()) {
        return HDF_SUCCESS;
    }
    startRead_.store(true);
    readThread_ = std::thread(&SerialDevice::ReadThread, this, READ_WAIT_TIME);
    return HDF_SUCCESS;
}

int32_t SerialDevice::StopRead()
{
    std::shared_lock lock(mutex_);
    return StopReadLocked();
}

int32_t SerialDevice::StopReadLocked()
{
    HDF_LOGI("StopReadLocked %{public}s! fd:%{public}d", portName_.c_str(), fd_);
    if (startRead_.load() && stopPipe_[PIPE_WRITE_IDX] >= 0) {
        char msg = 'S';
        write(stopPipe_[PIPE_WRITE_IDX], &msg, BYTE_SIZE_ONE);
    }
    startRead_.store(false);
    if (readThread_.joinable()) {
        readThread_.join();
    }
    return HDF_SUCCESS;
}

int32_t SerialDevice::Close()
{
    std::unique_lock lock(mutex_);
    isOpen_.store(false);

    if (closePipe_[PIPE_WRITE_IDX] >= 0) {
        char ch = 'C';
        write(closePipe_[PIPE_WRITE_IDX], &ch, sizeof(ch));
    }

    if (startRead_.load()) {
        StopReadLocked();
    }
    if (fd_ >= 0) {
        flock(fd_, LOCK_UN);
        fdsan_close_with_tag(fd_, fdsan_create_owner_tag(FDSAN_OWNER_TYPE_FILE, LOG_DOMAIN));
        fd_ = INVALID_FD;
    }
    ClosePipes();
    HDF_LOGI("Close %{public}s! fd:%{public}d", portName_.c_str(), fd_);
    return HDF_SUCCESS;
}

int32_t SerialDevice::NotifyDeviceOffline()
{
    std::shared_lock lock(mutex_);
    if (cb_ == nullptr) {
        HDF_LOGE("%{public}s, cb_ == nullptr", __func__);
        return HDF_FAILURE;
    }
    HDF_LOGI("device %{public}s offline fd:%{public}d", portName_.c_str(), fd_);
    return cb_->OnDeviceOffline();
}

int32_t SerialDevice::ConfigurePort()
{
    HdfTrace openTrace("Serial::ConfigurePort");
    struct termios options;
    int32_t ret = tcgetattr(fd_, &options);
    if (ret != 0) {
        HDF_LOGE("%{public}s, tcgetattr failed! ret:%{public}d", __func__, ret);
        return HDF_FAILURE;
    }
    cfmakeraw(&options);
    options.c_cflag |= (CLOCAL | CREAD);
    if ((ret = SetBaudRateInternal(options)) != 0) {
        return ret;
    }

    if ((ret = SetParityInternal(options)) != 0) {
        return ret;
    }

    if ((ret = SetDataBitsInternal(options)) != 0) {
        return ret;
    }

    if ((ret = SetStopBitsInternal(options)) != 0) {
        return ret;
    }

    if ((ret = SetRtsCtsInternal(options)) != 0) {
        return ret;
    }

    if ((ret = SetXonXoffInternal(options)) != 0) {
        return ret;
    }

    options.c_oflag &= ~OPOST;
    options.c_lflag &= ~(ICANON | ECHO | ECHOE | ISIG);

    options.c_cc[VMIN] = VMIN_DEFAULT;
    options.c_cc[VTIME] = 0;

    if (tcsetattr(fd_, TCSANOW, &options) != 0) {
        HDF_LOGE("%{public}s, tcsetattr failed!", __func__);
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

int32_t SerialDevice::SetDataBitsInternal(struct termios& options)
{
    options.c_cflag &= ~CSIZE;
    switch (currentConfig_.dataBits) {
        case DATA_BIT_5: options.c_cflag |= CS5; break;
        case DATA_BIT_6: options.c_cflag |= CS6; break;
        case DATA_BIT_7: options.c_cflag |= CS7; break;
        case DATA_BIT_8: options.c_cflag |= CS8; break;
        default:
            HDF_LOGE("invalid databits:%{public}d\n", currentConfig_.dataBits);
            return HDF_ERR_INVALID_PARAM;
    }
    return HDF_SUCCESS;
}

int32_t SerialDevice::SetStopBitsInternal(struct termios& options)
{
    switch (currentConfig_.stopBits) {
        case STOP_BIT_ONE:
            options.c_cflag &= ~CSTOPB;
            break;
        case STOP_BIT_TWO:
            options.c_cflag |= CSTOPB;
            break;
        default:
            HDF_LOGE("invalid stopBits:%{public}d\n", currentConfig_.stopBits);
            return HDF_ERR_INVALID_PARAM;
    }
    return HDF_SUCCESS;
}

int32_t SerialDevice::SetRtsCtsInternal(struct termios& options)
{
    if (currentConfig_.rtscts) {
        options.c_cflag |= CRTSCTS;
    } else {
        options.c_cflag &= ~CRTSCTS;
    }
    return HDF_SUCCESS;
}

int32_t SerialDevice::SetXonXoffInternal(struct termios& options)
{
    options.c_cflag |= (CLOCAL | CREAD);
    options.c_iflag &= ~(IXON | IXOFF | IXANY);

    if (currentConfig_.xon) {
        options.c_iflag |= IXON;
    }
    if (currentConfig_.xoff) {
        options.c_iflag |= IXOFF;
    }
    if (currentConfig_.xany) {
        options.c_iflag |= IXANY;
    }

    return HDF_SUCCESS;
}

int32_t SerialDevice::SetParityInternal(struct termios& options)
{
    options.c_cflag &= ~(PARENB | PARODD | CMSPAR);
    switch (currentConfig_.parity) {
        case FLAG_PARITY_0:
            options.c_cflag &= ~PARENB;
            break;
        case FLAG_PARITY_1:
            options.c_cflag |= PARENB;
            options.c_cflag &= ~PARODD;
            break;
        case FLAG_PARITY_2:
            options.c_cflag |= (PARENB | PARODD);
            break;
        case FLAG_PARITY_3:
            options.c_cflag |= (PARENB | PARODD | CMSPAR);
            break;
        case FLAG_PARITY_4:
            options.c_cflag |= (PARENB | CMSPAR);
            options.c_cflag &= ~PARODD;
            break;
        default:
            HDF_LOGE("invalid parity:%{public}d\n", currentConfig_.parity);
            return HDF_ERR_INVALID_PARAM;
    }
    return HDF_SUCCESS;
}

int32_t SerialDevice::SetBaudRateInternal(struct termios& options)
{
    if (currentConfig_.baudRate <= 0) {
        HDF_LOGE("baudRate:%{public}d invalid!", currentConfig_.baudRate);
        return HDF_ERR_INVALID_PARAM;
    }
    static const struct { int32_t baud; speed_t speed; } baudTable[] = {
        {BR50, B50}, {BR75, B75}, {BR110, B110}, {BR134, B134},
        {BR150, B150}, {BR200, B200}, {BR300, B300}, {BR600, B600},
        {BR1200, B1200}, {BR1800, B1800}, {BR2400, B2400}, {BR4800, B4800},
        {BR9600, B9600}, {BR19200, B19200}, {BR38400, B38400}, {BR57600, B57600},
        {BR115200, B115200}, {BR230400, B230400}, {BR460800, B460800},
        {BR500000, B500000}, {BR576000, B576000}, {BR921600, B921600},
        {BR1000000, B1000000}, {BR1152000, B1152000}, {BR1500000, B1500000},
        {BR2000000, B2000000}, {BR2500000, B2500000}, {BR3000000, B3000000},
        {BR3500000, B3500000}, {BR4000000, B4000000}
    };

    for (size_t i = 0; i < sizeof(baudTable) / sizeof(baudTable[0]); i++) {
        if (currentConfig_.baudRate == baudTable[i].baud) {
            if (cfsetispeed(&options, baudTable[i].speed) < 0) {
                HDF_LOGE("cfsetispeed:%{public}d failed!", currentConfig_.baudRate);
                return HDF_ERR_INVALID_PARAM;
            }
            if (cfsetospeed(&options, baudTable[i].speed) < 0) {
                HDF_LOGE("cfsetospeed:%{public}d failed!", currentConfig_.baudRate);
                return HDF_ERR_INVALID_PARAM;
            }
            return HDF_SUCCESS;
        }
    }
    HDF_LOGE("invalid baud:%{public}d!", currentConfig_.baudRate);
    return HDF_ERR_INVALID_PARAM;
}

int32_t SerialDevice::Write(const std::vector<uint8_t>& data, int32_t timeout, int32_t& bytesWritten)
{
    HDF_LOGD("%{public}s called, size=%{public}zu!", __func__, data.size());
    bytesWritten = 0;

    std::shared_lock lock(mutex_);
    if (!isOpen_.load() || fd_ < 0) {
        HDF_LOGE("%{public}s, device not open!", __func__);
        return HDF_ERR_INVALID_OBJECT;
    }
    if (data.empty() || data.size() > MAX_BUFFER_LEN) {
        HDF_LOGW("data is invalid!size:%{public}zu", data.size());
        return HDF_ERR_INVALID_PARAM;
    }

    size_t written = 0;
    HdfTrace openTrace("Serial::DoWriteLoop");
    int32_t ret = DoWriteLoop(data.data(), data.size(), timeout, written);
    bytesWritten = static_cast<int32_t>(written);
    return ret;
}

int32_t SerialDevice::PollForWrite(struct pollfd* fds, int32_t timeout)
{
    fds[ARRAY_INDEX_0].revents = 0;
    fds[ARRAY_INDEX_1].revents = 0;

    int32_t ret = poll(fds, PIPE_FD_LEN, timeout);
    if (ret < 0) {
        if (errno == EINTR) {
            return HDF_SUCCESS;
        }
        HDF_LOGE("poll error, errno:%{public}d", errno);
        return HDF_ERR_IO;
    }
    if (ret == 0) {
        return HDF_ERR_TIMEOUT;
    }

    if ((fds[ARRAY_INDEX_1].revents & POLLIN) != 0) {
        char buff;
        read(closePipe_[PIPE_READ_IDX], &buff, BYTE_SIZE_ONE);
        return HDF_ERR_DEVICE_BUSY;
    }
    if ((fds[ARRAY_INDEX_0].revents & POLLHUP) != 0) {
        return HDF_DEV_ERR_NO_DEVICE;
    }
    if ((fds[ARRAY_INDEX_0].revents & (POLLERR | POLLNVAL)) != 0) {
        return HDF_ERR_IO;
    }
    return HDF_SUCCESS;
}

int32_t SerialDevice::DoWriteLoop(const uint8_t* data, size_t size, int32_t timeout, size_t& written)
{
    struct pollfd fds[PIPE_FD_LEN];
    fds[ARRAY_INDEX_0].fd = fd_;
    fds[ARRAY_INDEX_0].events = POLLOUT;
    fds[ARRAY_INDEX_1].fd = closePipe_[PIPE_READ_IDX];
    fds[ARRAY_INDEX_1].events = POLLIN;

    written = 0;
    size_t remaining = size;

    while (remaining > 0) {
        if (!isOpen_.load() || fd_ < 0) {
            return HDF_ERR_INVALID_OBJECT;
        }

        int32_t ret = PollForWrite(fds, timeout);
        if (ret != HDF_SUCCESS) {
            return ret;
        }

        if ((fds[ARRAY_INDEX_0].revents & POLLOUT) == 0) {
            continue;
        }

        ssize_t bytes = write(fd_, data + written, remaining);
        if (bytes < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                continue;
            }
            HDF_LOGE("write failed, errno:%{public}d", errno);
            return HDF_FAILURE;
        }
        if (bytes == 0) {
            HDF_LOGW("write returned 0, device may be full");
            continue;
        }
        written += static_cast<size_t>(bytes);
        remaining -= static_cast<size_t>(bytes);
    }
    return HDF_SUCCESS;
}

int32_t SerialDevice::Flush()
{
    HDF_LOGI("%{public}s called!", __func__);
    std::shared_lock lock(mutex_);

    if (!isOpen_.load() || fd_ < 0) {
        HDF_LOGE("%{public}s, device not open!", __func__);
        return HDF_ERR_INVALID_OBJECT;
    }

    if (tcflush(fd_, TCIOFLUSH) != 0) {
        HDF_LOGE("%{public}s, tcflush failed!", __func__);
        return HDF_FAILURE;
    }

    return HDF_SUCCESS;
}

int32_t SerialDevice::Drain()
{
    HDF_LOGD("%{public}s called!", __func__);
    std::shared_lock lock(mutex_);

    if (!isOpen_.load() || fd_ < 0) {
        HDF_LOGE("%{public}s, device not open!", __func__);
        return HDF_ERR_INVALID_OBJECT;
    }

    if (tcdrain(fd_) != 0) {
        HDF_LOGE("%{public}s, tcdrain failed-errno=%{public}d (%{public}s)\n", __func__, errno, strerror(errno));
        return HDF_FAILURE;
    }

    return HDF_SUCCESS;
}

int32_t SerialDevice::SendBrkSignal()
{
    HDF_LOGD("%{public}s called!", __func__);
    std::shared_lock lock(mutex_);

    if (!isOpen_.load() || fd_ < 0) {
        HDF_LOGE("%{public}s, device not open!", __func__);
        return HDF_ERR_INVALID_OBJECT;
    }

    HdfTrace openTrace("Serial::tcsendbreak");
    if (tcsendbreak(fd_, 0) != 0) {
        HDF_LOGE("%{public}s, tcsendbreak failed-errno=%{public}d (%{public}s)\n", __func__, errno, strerror(errno));
        return HDF_FAILURE;
    }

    return HDF_SUCCESS;
}

int32_t SerialDevice::SetRtsSignal(bool rts)
{
    HDF_LOGD("%{public}s called, rts=%{public}d!", __func__, rts);
    std::shared_lock lock(mutex_);
    HdfTrace openTrace("Serial::SetRtsSignal");
    if (!isOpen_.load() || fd_ < 0) {
        HDF_LOGE("%{public}s, device not open!", __func__);
        return HDF_ERR_INVALID_OBJECT;
    }

    int flags;
    if (ioctl(fd_, TIOCMGET, &flags) != 0) {
        HDF_LOGE("%{public}s, TIOCMGET failed-errno=%{public}d (%{public}s)\n", __func__, errno, strerror(errno));
        return HDF_FAILURE;
    }

    if (rts) {
        flags |= TIOCM_RTS;
    } else {
        flags &= ~TIOCM_RTS;
    }

    if (ioctl(fd_, TIOCMSET, &flags) != 0) {
        HDF_LOGE("%{public}s, TIOCMSET failed-errno=%{public}d (%{public}s)\n", __func__, errno, strerror(errno));
        return HDF_FAILURE;
    }

    return HDF_SUCCESS;
}

int32_t SerialDevice::GetCtsSignal(bool& cts)
{
    HDF_LOGD("%{public}s called!", __func__);
    std::shared_lock lock(mutex_);
    HdfTrace openTrace("Serial::GetCtsSignal");
    if (!isOpen_.load() || fd_ < 0) {
        HDF_LOGE("%{public}s, device not open!", __func__);
        return HDF_ERR_INVALID_OBJECT;
    }

    int flags;
    if (ioctl(fd_, TIOCMGET, &flags) != 0) {
        HDF_LOGE("%{public}s, TIOCMGET failed-errno=%{public}d (%{public}s)\n", __func__, errno, strerror(errno));
        return HDF_FAILURE;
    }

    cts = (flags & TIOCM_CTS) != 0;
    return HDF_SUCCESS;
}

void SerialDevice::ReadThread(int32_t timeout)
{
    std::vector<int8_t> buffer(MAX_BUFFER_LEN);
    int32_t bytesRead = 0;

    struct pollfd fds[POLL_FDS_COUNT_READ];
    fds[ARRAY_INDEX_0].fd = fd_;
    fds[ARRAY_INDEX_0].events = POLLIN;
    fds[ARRAY_INDEX_1].fd = stopPipe_[PIPE_READ_IDX];
    fds[ARRAY_INDEX_1].events = POLLIN;
    fds[ARRAY_INDEX_2].fd = closePipe_[PIPE_READ_IDX];
    fds[ARRAY_INDEX_2].events = POLLIN;

    while (startRead_.load()) {
        if (!isOpen_.load() || fd_ < 0) {
            HDF_LOGE("not able to read!");
            break;
        }

        int32_t ret = PollForRead(fds, timeout);
        if (ret == HDF_ERR_TIMEOUT || ret == HDF_SUCCESS) {
            if (ret == HDF_SUCCESS && HandleReadEvent(fds, buffer, bytesRead)) {
                continue;
            }
            break;
        }
    }
    HDF_LOGI("finish read! bytesRead:%{public}d", bytesRead);
}

int32_t SerialDevice::PollForRead(struct pollfd* fds, int32_t timeout)
{
    fds[ARRAY_INDEX_0].revents = 0;
    fds[ARRAY_INDEX_1].revents = 0;
    fds[ARRAY_INDEX_2].revents = 0;

    int32_t ret = poll(fds, POLL_FDS_COUNT_READ, timeout);
    if (ret < 0) {
        if (errno == EINTR) {
            return HDF_SUCCESS;
        }
        HDF_LOGE("poll error, errno:%{public}d", errno);
        return HDF_FAILURE;
    }
    if (ret == 0) {
        return HDF_ERR_TIMEOUT;
    }

    if ((fds[ARRAY_INDEX_2].revents & POLLIN) != 0) {
        char buff;
        read(closePipe_[PIPE_READ_IDX], &buff, BYTE_SIZE_ONE);
        HDF_LOGI("Read interrupted by close signal");
        return HDF_FAILURE;
    }
    if ((fds[ARRAY_INDEX_1].revents & POLLIN) != 0) {
        char buff;
        read(stopPipe_[PIPE_READ_IDX], &buff, BYTE_SIZE_ONE);
        HDF_LOGI("Read stopped by StopRead");
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

bool SerialDevice::HandleReadEvent(struct pollfd* fds, std::vector<int8_t>& buffer, int32_t& bytesRead)
{
    if ((fds[ARRAY_INDEX_0].revents & POLLHUP) != 0) {
        HDF_LOGE("device offline!");
        return false;
    }
    if ((fds[ARRAY_INDEX_0].revents & (POLLERR | POLLNVAL)) != 0) {
        HDF_LOGE("Port error or closed.");
        return false;
    }

    if ((fds[ARRAY_INDEX_0].revents & POLLIN) == 0) {
        return true;
    }

    if (memset_s(buffer.data(), buffer.size(), 0, buffer.size()) != EOK) {
        HDF_LOGE("memset_s failed!");
        return false;
    }

    ssize_t readBytes = read(fd_, buffer.data(), buffer.size());
    if (readBytes < 0) {
        HDF_LOGE("read failed, errno:%{public}d!", errno);
        return true;
    }
    if (readBytes == 0) {
        HDF_LOGW("device offline!");
        return false;
    }

    bytesRead += static_cast<int32_t>(readBytes);
    cb_->OnReadData(buffer, readBytes);
    return true;
}

int32_t SerialDevice::InitPipes()
{
    if (pipe(stopPipe_) != 0) {
        HDF_LOGE("stopPipe create failed, errno=%{public}d", errno);
        return HDF_FAILURE;
    }
    fdsan_exchange_owner_tag(stopPipe_[PIPE_READ_IDX], 0, fdsan_create_owner_tag(FDSAN_OWNER_TYPE_FILE, LOG_DOMAIN));
    fdsan_exchange_owner_tag(stopPipe_[PIPE_WRITE_IDX], 0, fdsan_create_owner_tag(FDSAN_OWNER_TYPE_FILE, LOG_DOMAIN));
    if (pipe(closePipe_) != 0) {
        HDF_LOGE("closePipe create failed, errno=%{public}d", errno);
        fdsan_close_with_tag(stopPipe_[PIPE_READ_IDX], fdsan_create_owner_tag(FDSAN_OWNER_TYPE_FILE, LOG_DOMAIN));
        fdsan_close_with_tag(stopPipe_[PIPE_WRITE_IDX], fdsan_create_owner_tag(FDSAN_OWNER_TYPE_FILE, LOG_DOMAIN));
        stopPipe_[PIPE_READ_IDX] = INVALID_FD;
        stopPipe_[PIPE_WRITE_IDX] = INVALID_FD;
        return HDF_FAILURE;
    }
    fdsan_exchange_owner_tag(closePipe_[PIPE_READ_IDX], 0, fdsan_create_owner_tag(FDSAN_OWNER_TYPE_FILE, LOG_DOMAIN));
    fdsan_exchange_owner_tag(closePipe_[PIPE_WRITE_IDX], 0, fdsan_create_owner_tag(FDSAN_OWNER_TYPE_FILE, LOG_DOMAIN));
    return HDF_SUCCESS;
}

void SerialDevice::ClosePipes()
{
    if (stopPipe_[PIPE_READ_IDX] >= 0) {
        fdsan_close_with_tag(stopPipe_[PIPE_READ_IDX], fdsan_create_owner_tag(FDSAN_OWNER_TYPE_FILE, LOG_DOMAIN));
        stopPipe_[PIPE_READ_IDX] = INVALID_FD;
    }
    if (stopPipe_[PIPE_WRITE_IDX] >= 0) {
        fdsan_close_with_tag(stopPipe_[PIPE_WRITE_IDX], fdsan_create_owner_tag(FDSAN_OWNER_TYPE_FILE, LOG_DOMAIN));
        stopPipe_[PIPE_WRITE_IDX] = INVALID_FD;
    }
    if (closePipe_[PIPE_READ_IDX] >= 0) {
        fdsan_close_with_tag(closePipe_[PIPE_READ_IDX], fdsan_create_owner_tag(FDSAN_OWNER_TYPE_FILE, LOG_DOMAIN));
        closePipe_[PIPE_READ_IDX] = INVALID_FD;
    }
    if (closePipe_[PIPE_WRITE_IDX] >= 0) {
        fdsan_close_with_tag(closePipe_[PIPE_WRITE_IDX], fdsan_create_owner_tag(FDSAN_OWNER_TYPE_FILE, LOG_DOMAIN));
        closePipe_[PIPE_WRITE_IDX] = INVALID_FD;
    }
}
} // V1_0
} // Serials
} // HDI
} // OHOS
