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

#include "scsi_linux_adapter.h"

#include <cerrno>
#include <cstdint>
#include <fcntl.h>
#include <hdf_base.h>
#include <hdf_log.h>
#include <cstdlib>
#include <cstring>
#include <scsi/sg.h>
#include <securec.h>
#include <sys/ioctl.h>
#include <termios.h>
#include <unistd.h>
#include <sstream>
#include <iomanip>

#include "usbd_wrapper.h"

#define HDF_LOG_TAG scsi_linux_adapter

namespace OHOS {
namespace HDI {
namespace Usb {
namespace ScsiDdk {
namespace V1_0 {

constexpr uint8_t SCSIPERIPHERAL_MAX_SENSE_DATA_LEN = 252;
constexpr uint8_t TWO_BYTE = 2;
constexpr uint8_t OPERATION_CODE_REQUEST_SENSE = 0x03;

static std::string BytesToHex(const uint8_t* data, size_t length)
{
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (size_t i = 0; i < length; ++i) {
        oss << std::setw(TWO_BYTE) << static_cast<int>(data[i]) << ' ';
    }
    return oss.str();
}

static std::string DxferDirectionToString(int direction)
{
    switch (direction) {
        case SG_DXFER_NONE: return "SG_DXFER_NONE";
        case SG_DXFER_TO_DEV: return "SG_DXFER_TO_DEV";
        case SG_DXFER_FROM_DEV: return "SG_DXFER_FROM_DEV";
        case SG_DXFER_TO_FROM_DEV: return "SG_DXFER_TO_FROM_DEV";
        default: return "UNKNOWN (" + std::to_string(direction) + ")";
    }
}
static std::string ToString(const struct sg_io_hdr& ioHdr)
{
    std::ostringstream buffer;
    buffer << "sg_io_hdr{\n" << "  interface_id='" << ioHdr.interface_id << "' (" <<
        static_cast<int>(ioHdr.interface_id) << ")\n" << "  cmdp=" <<  static_cast<void*>(ioHdr.cmdp) << " (";
    if (ioHdr.cmdp && ioHdr.cmd_len > 0) {
        buffer << "CMD: " << BytesToHex(reinterpret_cast<const uint8_t*>(ioHdr.cmdp), ioHdr.cmd_len);
    } else {
        buffer << "NULL or empty CMD";
    }
    buffer << ")\n" << "  cmd_len=" << static_cast<int>(ioHdr.cmd_len) << '\n' << "  dxfer_direction=" <<
        DxferDirectionToString(ioHdr.dxfer_direction) << " (" << std::dec << ioHdr.dxfer_direction << ")\n" <<
        "  dxferp=" << static_cast<void*>(ioHdr.dxferp) << '\n' << "  dxfer_len=" << ioHdr.dxfer_len << '\n' <<
        "  sbp=" << static_cast<void*>(ioHdr.sbp) << '\n' << "  mx_sb_len=" << static_cast<int>(ioHdr.mx_sb_len) <<
        '\n' << "  timeout=" << ioHdr.timeout << "\n" << "}";

    return buffer.str();
}

static void UpdateResponse(const struct sg_io_hdr& ioHdr, Response& response)
{
    response.status = ioHdr.status;
    response.maskedStatus = ioHdr.masked_status;
    response.msgStatus = ioHdr.msg_status;
    response.sbLenWr = ioHdr.sb_len_wr;
    response.hostStatus = ioHdr.host_status;
    response.driverStatus = ioHdr.driver_status;
    response.resId = ioHdr.resid;
    response.duration = ioHdr.duration;
    response.transferredLength = ioHdr.dxfer_len - ioHdr.resid;
}

int32_t LinuxScsiOsAdapter::SendRequest(const Request& request, uint8_t *buffer, uint32_t bufferSize,
    Response& response)
{
    uint8_t cmdLen = request.commandDescriptorBlock.size();
    if (cmdLen == 0) {
        HDF_LOGE("SendRequest: Command Descriptor Block is empty");
        return SCSIPERIPHERAL_DDK_INVALID_PARAMETER;
    }

    std::vector<uint8_t> cmd(request.commandDescriptorBlock.data(), request.commandDescriptorBlock.data() + cmdLen);

    struct sg_io_hdr ioHdr;
    int32_t result = memset_s(&ioHdr, sizeof(ioHdr), 0, sizeof(ioHdr));
    if (result != 0) {
        HDF_LOGE("%{public}s memset_s(ioHdr) failed, result=%{public}d", __func__, result);
        return SCSIPERIPHERAL_DDK_MEMORY_ERROR;
    }
    ioHdr.interface_id = 'S';
    ioHdr.cmdp = cmd.data();
    ioHdr.cmd_len = cmdLen;
    ioHdr.dxfer_direction = request.dataTransferDirection;

    if ((buffer != nullptr) && (bufferSize != 0)) {
        ioHdr.dxferp = buffer;
        ioHdr.dxfer_len = bufferSize;
    }

    if (cmd[0] == OPERATION_CODE_REQUEST_SENSE) {
        ioHdr.sbp = nullptr;
        ioHdr.mx_sb_len = 0;
    } else {
        response.senseData.resize(SCSIPERIPHERAL_MAX_SENSE_DATA_LEN);
        ioHdr.sbp = response.senseData.data();
        ioHdr.mx_sb_len = response.senseData.size();
    }
    ioHdr.timeout = request.timeout;
    HDF_LOGD("SendRequest, request.devFd=%{public}d, \n%{public}s", request.devFd, ToString(ioHdr).c_str());

    if (ioctl(request.devFd, SG_IO, &ioHdr) < 0) {
        if (errno == ETIME) {
            HDF_LOGE("%{public}s: ioctl timeout", __func__);
            return SCSIPERIPHERAL_DDK_TIMEOUT;
        } else {
            HDF_LOGE("%{public}s: ioctl failed, errno=%{public}d (%{public}s)", __func__, errno, strerror(errno));
            return SCSIPERIPHERAL_DDK_IO_ERROR;
        }
    }

    UpdateResponse(ioHdr, response);
    HDF_LOGD("response.status=%{public}x, transferredLength=%{public}d", response.status, response.transferredLength);
    HDF_LOGD("SendRequest, response.senseData=[ %{public}s ]",
        BytesToHex(reinterpret_cast<const uint8_t*>(response.senseData.data()), response.senseData.size()).c_str());

    return HDF_SUCCESS;
}
} // namespace V1_0
} // namespace ScsiDdk
} // namespace Usb
} // namespace HDI
} // namespace OHOS
