/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "usb_serial_linux_adapter.h"

#include <cerrno>
#include <cstdint>
#include <fcntl.h>
#include <hdf_base.h>
#include <hdf_log.h>
#include <cstdlib>
#include <cstring>
#include <sys/ioctl.h>
#include <termios.h>
#include <unistd.h>

#include "usbd_wrapper.h"

#define HDF_LOG_TAG usb_serial_linux_adapter

namespace OHOS {
namespace HDI {
namespace Usb {
namespace UsbSerialDdk {
namespace V1_0 {

static std::unordered_map<uint32_t, uint32_t> g_baudRateMap = {
    {0, B0},
    {50, B50},
    {75, B75},
    {110, B110},
    {134, B134},
    {150, B150},
    {200, B200},
    {300, B300},
    {600, B600},
    {1200, B1200},
    {1800, B1800},
    {2400, B2400},
    {4800, B4800},
    {9600, B9600},
    {19200, B19200},
    {38400, B38400},
    {57600, B57600},
    {115200, B115200},
    {230400, B230400},
    {460800, B460800},
    {500000, B500000},
    {576000, B576000},
    {921600, B921600},
    {1000000, B1000000},
    {1152000, B1152000},
    {1500000, B1500000},
    {2000000, B2000000},
    {2500000, B2500000},
    {3000000, B3000000},
    {3500000, B3500000},
    {4000000, B4000000}
};

static uint32_t TransToStandardBaudRate(uint32_t baudRate)
{
    auto it = g_baudRateMap.find(baudRate);
    if (it != g_baudRateMap.end()) {
        return it->second;
    }
    return baudRate;
}

static void SetDefaultTty(struct termios &tty)
{
    tty.c_cflag = (tty.c_cflag & ~CSIZE) | CS8;
    tty.c_iflag &= ~IGNBRK;
    tty.c_lflag = 0;
    tty.c_oflag = 0;

    // read doesn't block
    tty.c_cc[VMIN]  = 0;
    tty.c_cc[VTIME] = 0;

    tty.c_iflag &= ~(IXON | IXOFF | IXANY);
    tty.c_cflag &= ~CRTSCTS;

    tty.c_cflag |= (CLOCAL | CREAD);
    tty.c_cflag &= ~(PARENB | PARODD);
    tty.c_cflag |= 0;
    tty.c_cflag &= ~CSTOPB;
}

static int SetSpeed(struct termios &tty, uint32_t baudRate)
{
    tty.c_cflag &= ~CBAUD;
    tty.c_cflag |= CBAUDEX;

    // set baudRate
    uint32_t baudRateConstant = 0;
    baudRateConstant = TransToStandardBaudRate(baudRate);
    if (cfsetospeed(&tty, baudRateConstant) != 0) {
        HDF_LOGE("Cfsetospeed err.\n");
        return USB_SERIAL_DDK_IO_ERROR;
    }
    if (cfsetispeed(&tty, baudRateConstant) != 0) {
        HDF_LOGE("cfsetispeed err.\n");
        return USB_SERIAL_DDK_IO_ERROR;
    }
    return HDF_SUCCESS;
}

static int SetDataBits(struct termios &tty, uint8_t dataBits)
{
    tty.c_cflag &= ~CSIZE;
    switch (dataBits) {
        case DATA_BITS_5:
            tty.c_cflag |= CS5;
            break;
        case DATA_BITS_6:
            tty.c_cflag |= CS6;
            break;
        case DATA_BITS_7:
            tty.c_cflag |= CS7;
            break;
        case DATA_BITS_8:
            tty.c_cflag |= CS8;
            break;
        default:
            HDF_LOGE("Unsupported data bits %{public}d.\n", dataBits);
            return USB_SERIAL_DDK_INVALID_PARAMETER;
    }
    return HDF_SUCCESS;
}

static int SetParity(struct termios &tty, uint8_t parity)
{
    tty.c_cflag &= ~(PARENB | PARODD);
    switch (parity) {
        case USB_SERIAL_PARITY_NONE:
            tty.c_cflag |= 0;
            break;
        case USB_SERIAL_PARITY_ODD:
            tty.c_cflag |= (PARODD | PARENB);
            break;
        case USB_SERIAL_PARITY_EVEN:
            tty.c_cflag |= PARENB;
            break;
        default:
            HDF_LOGE("Unsupported parity %{public}d.\n", parity);
            return USB_SERIAL_DDK_INVALID_PARAMETER;
    }
    return HDF_SUCCESS;
}

int32_t LinuxUsbSerialOsAdapter::SetBaudRate(int32_t fd, uint32_t baudRate)
{
    HDF_LOGE("into SetBaudRate.\n");
    struct termios tty;
    if (tcgetattr(fd, &tty) != 0) {
        HDF_LOGE("%{public}s: error tcgetattr %{public}s.\n", __func__, strerror(errno));
        if (errno == EBADF) {
            return USB_SERIAL_DDK_INVALID_OPERATION;
        }
        return USB_SERIAL_DDK_IO_ERROR;
    }

    int ret = SetSpeed(tty, baudRate);
    if (ret != HDF_SUCCESS) {
        return ret;
    }
    SetDefaultTty(tty);

    if (tcsetattr(fd, TCSANOW, &tty) != 0) {
        HDF_LOGE("error %d from tcsetattr\n", errno);
        return USB_SERIAL_DDK_IO_ERROR;
    }
    return HDF_SUCCESS;
}

int32_t LinuxUsbSerialOsAdapter::SetParams(int32_t fd, const UsbSerialParams &params)
{
    struct termios tty;
    if (tcgetattr(fd, &tty) != 0) {
        HDF_LOGE("%{public}s: error tcgetattr fd %{public}d, %{public}s.\n", __func__, fd, strerror(errno));
        if (errno == EBADF) {
            return USB_SERIAL_DDK_INVALID_OPERATION;
        }
        return USB_SERIAL_DDK_IO_ERROR;
    }

    int ret = SetSpeed(tty, params.baudRate);
    if (ret != HDF_SUCCESS) {
        return ret;
    }
    SetDefaultTty(tty);

    ret = SetDataBits(tty, params.nDataBits);
    if (ret != HDF_SUCCESS) {
        return ret;
    }

    if (params.nStopBits == STOP_ONE) {
        tty.c_cflag &= ~CSTOPB;
    } else if (params.nStopBits == STOP_TWO) {
        tty.c_cflag |= CSTOPB;
    } else {
        HDF_LOGE("Unsupported stop bits %{public}d.\n", params.nStopBits);
        return USB_SERIAL_DDK_INVALID_PARAMETER;
    }

    ret = SetParity(tty, params.parity);
    if (ret != HDF_SUCCESS) {
        return ret;
    }

    if (tcsetattr(fd, TCSANOW, &tty) != 0) {
        HDF_LOGE("error %d from tcsetattr\n", errno);
        return USB_SERIAL_DDK_IO_ERROR;
    }
    return HDF_SUCCESS;
}

int32_t LinuxUsbSerialOsAdapter::SetTimeout(int32_t fd, int32_t timeout)
{
    struct termios tty;
    if (tcgetattr(fd, &tty) != 0) {
        HDF_LOGE("%{public}s: tcgetattr error %{public}s.\n", __func__, strerror(errno));
        if (errno == EBADF) {
            return USB_SERIAL_DDK_INVALID_OPERATION;
        }
        return USB_SERIAL_DDK_IO_ERROR;
    }

    if (timeout == -1) {
        // block indefinitely
        tty.c_cc[VTIME] = 0;
        tty.c_cc[VMIN] = 1;
    } else if (timeout == 0) {
        // Setting both to 0 will give a non-blocking read
        tty.c_cc[VTIME] = 0;
        tty.c_cc[VMIN] = 0;
    } else if (timeout > 0) {
        tty.c_cc[VTIME] = (cc_t)(timeout / 100); // 100 ms
        tty.c_cc[VMIN] = 0;
    }

    if (tcsetattr(fd, TCSANOW, &tty) != 0) {
        HDF_LOGE("tcsetattr error %{public}s.\n", strerror(errno));
        return USB_SERIAL_DDK_IO_ERROR;
    }

    return HDF_SUCCESS;
}

int32_t LinuxUsbSerialOsAdapter::SetFlowControl(int32_t fd, int32_t flowControl)
{
    struct termios tty;
    if (tcgetattr(fd, &tty) != 0) {
        HDF_LOGE("%{public}s: error tcgetattr %{public}s.\n", __func__, strerror(errno));
        if (errno == EBADF) {
            return USB_SERIAL_DDK_INVALID_OPERATION;
        }
        return USB_SERIAL_DDK_IO_ERROR;
    }
    tty.c_iflag &= ~(IXON | IXOFF | IXANY);
    tty.c_cflag &= ~CRTSCTS;
    if (flowControl == USB_SERIAL_SOFTWARE_FLOW_CONTROL) {
        tty.c_iflag |= (IXON | IXOFF | IXANY);
    } else if (flowControl == USB_SERIAL_HARDWARE_FLOW_CONTROL) {
        tty.c_cflag |= CRTSCTS;
    }

    if (tcsetattr(fd, TCSANOW, &tty) != 0) {
        HDF_LOGE("error tcsetattr %{public}s.\n", strerror(errno));
        return USB_SERIAL_DDK_IO_ERROR;
    }
    return HDF_SUCCESS;
}

bool LinuxUsbSerialOsAdapter::IsDeviceDisconnect(int32_t fd)
{
    struct termios term2;
    int rv = ioctl(fd, TCGETS, &term2);
    if (rv != 0) {
        HDF_LOGE("device disconnection.\n");
        return true;
    }
    return false;
}

int32_t LinuxUsbSerialOsAdapter::Flush(int32_t fd)
{
    int ret = tcdrain(fd);
    if (ret != 0) {
        HDF_LOGE("%{public}s: Failed to flush serial port %{public}s.\n", __func__, strerror(errno));
        if (errno == EBADF) {
            return USB_SERIAL_DDK_INVALID_OPERATION;
        }
        return USB_SERIAL_DDK_IO_ERROR;
    }
    return HDF_SUCCESS;
}

int32_t LinuxUsbSerialOsAdapter::FlushInput(int32_t fd)
{
    int ret = tcflush(fd, TCIFLUSH);
    if (ret != 0) {
        HDF_LOGE("%{public}s: Failed to flush input buffer: %{public}s.\n", __func__, strerror(errno));
        if (errno == EBADF) {
            return USB_SERIAL_DDK_INVALID_OPERATION;
        }
        return USB_SERIAL_DDK_IO_ERROR;
    }
    return HDF_SUCCESS;
}

int32_t LinuxUsbSerialOsAdapter::FlushOutput(int32_t fd)
{
    int ret = tcflush(fd, TCOFLUSH);
    if (ret != 0) {
        HDF_LOGE("%{public}s: Failed to flush output buffer: %{public}s.\n", __func__, strerror(errno));
        if (errno == EBADF) {
            return USB_SERIAL_DDK_INVALID_OPERATION;
        }
        return USB_SERIAL_DDK_IO_ERROR;
    }
    return HDF_SUCCESS;
}

} // namespace V1_0
} // namespace UsbSerialDdk
} // namespace Usb
} // namespace HDI
} // namespace OHOS
