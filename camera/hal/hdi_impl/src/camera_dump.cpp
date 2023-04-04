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

#include <sys/time.h>
#include <fstream>
#include <sstream>
#include "camera_dump.h"
#include "v1_0/types.h"
#include "camera.h"

namespace OHOS::Camera {
const std::string DUMP_PATH = "/data/log/hidumper/";
constexpr uint32_t ARGS_MAX_NUM = 5;
constexpr uint32_t PATH_MAX_LEN = 200;
const char *g_cameraDumpHelp =
    " Camera manager dump options:\n"
    "     -h: camera dump help\n"
    "     -m: start dump metadata\n"
    "     -b: start dump buffer\n"
    "     -s: start dump streamInfo\n";

std::map<DumpType, bool> g_dumpInfoMap = {
    {MedataType, false},
    {BufferType, false}
};

bool CameraDumper::DumpBuffer(const std::shared_ptr<IBuffer>& buffer)
{
    if (buffer == nullptr) {
        CAMERA_LOGE("buffer is nullptr");
        return false;
    }

    if (!IsDumpOpened(BufferType)) {
        return false;
    }

    uint32_t size = buffer->GetSize();
    uint32_t width = buffer->GetWidth();
    void* addr = buffer->GetVirAddress();
    uint32_t height = buffer->GetHeight();
    int32_t streamId = buffer->GetStreamId();
    int32_t captureId = buffer->GetCaptureId();
    int32_t encodeType = buffer->GetEncodeType();
    EsFrameInfo esInfo = buffer->GetEsFrameInfo();
    size = esInfo.size > 0 ? esInfo.size : size;

    std::stringstream ss;
    std::string fileName;
    ss << "captureId[" << captureId << "]_streamId[" << streamId <<
        "]_width[" << width << "]_height[" << height;

    if (encodeType == HDI::Camera::V1_0::ENCODE_TYPE_JPEG) {
        ss << "]_" << GetCurrentLocalTimeStamp();
        ss >> fileName;
        fileName += ".jpeg";
    } else if (encodeType == HDI::Camera::V1_0::ENCODE_TYPE_H264) {
        fileName = "cameraDumpVideo.h264";
    } else {
        ss << "]_" << GetCurrentLocalTimeStamp();
        ss >> fileName;
        fileName += ".yuv";
    }

    return SaveDataToFile(fileName.c_str(), addr, size);
}

bool CameraDumper::DumpMetadata(const std::shared_ptr<CameraMetadata>& metadata, std::string tag)
{
    if (metadata == nullptr) {
        CAMERA_LOGE("metadata is nullptr");
        return false;
    }

    if (!IsDumpOpened(MedataType)) {
        return false;
    }

    common_metadata_header_t *data = metadata->get();
    if (data == nullptr) {
        CAMERA_LOGE("data is nullptr");
        return false;
    }
    std::string metaStr = FormatCameraMetadataToString(data);
    if (metaStr.size() == 0) {
        CAMERA_LOGE("metaStr.size is 0");
        return true;
    }
    std::stringstream ss;
    ss << GetCurrentLocalTimeStamp() << "_" << tag << ".meta";

    return SaveDataToFile(ss.str().c_str(), metaStr.c_str(), metaStr.size());
}

void CameraDumper::UpdateDumpMode(DumpType type, bool isDump, HdfSBuf *reply)
{
    std::string upRetStr;
   
    auto it = g_dumpInfoMap.find(type);
    if (it != g_dumpInfoMap.end()) {
        g_dumpInfoMap[type] = isDump;
        upRetStr += " set dump mode success!\n";
    }
    
    if (reply != nullptr) {
        (void)HdfSbufWriteString(reply, upRetStr.c_str());
    }
}

bool CameraDumper::IsDumpOpened(DumpType type)
{
    if (g_dumpInfoMap.find(type) != g_dumpInfoMap.end() && g_dumpInfoMap[type]) {
        return true;
    }
    return false;
}

bool CameraDumper::SaveDataToFile(const char *fileName, const void *data, uint32_t size)
{
    std::stringstream ss;
    ss << DUMP_PATH << fileName;
    std::ofstream ofs(ss.str(), std::ios::app);

    if (!ofs.good()) {
        CAMERA_LOGE("open dump file <%{public}s> failed, error: %{public}s", ss.str().c_str(), std::strerror(errno));
        return false;
    }

    ofs.write(static_cast<const char *>(data), size);
    ofs.close();

    return true;
}

uint64_t CameraDumper::GetCurrentLocalTimeStamp()
{
    std::chrono::time_point<std::chrono::system_clock, std::chrono::milliseconds> tp =
        std::chrono::time_point_cast<std::chrono::milliseconds>(std::chrono::system_clock::now());
    auto tmp = std::chrono::duration_cast<std::chrono::milliseconds>(tp.time_since_epoch());
    return static_cast<uint64_t>(tmp.count());
}

void CameraDumper::ShowDumpMenu(HdfSBuf *reply)
{
    if (reply != nullptr) {
        (void)HdfSbufWriteString(reply, g_cameraDumpHelp);
    }
}

void CameraDumper::CameraHostDumpProcess(HdfSBuf *data, HdfSBuf *reply)
{
    if (data == nullptr || reply == nullptr) {
        CAMERA_LOGE("%{public}s is nullptr", (data == nullptr) ? "data" : "reply");
        return;
    }

    uint32_t argsNum;
    if (!HdfSbufReadUint32(data, &argsNum)) {
        CAMERA_LOGE("read argsNum failed!");
        return;
    }

    if (argsNum <= 0 || argsNum > ARGS_MAX_NUM) {
        (void)HdfSbufWriteString(reply, g_cameraDumpHelp);
        return;
    }

    for (uint32_t i = 0; i < argsNum; i++) {
        const char *value = HdfSbufReadString(data);
        if (value == NULL) {
            CAMERA_LOGE("arg is invalid i: %{public}u", i);
            return;
        }
        if (strcmp(value, "-m") == 0) {
            UpdateDumpMode(MedataType, true, reply);
        } else if (strcmp(value, "-b") == 0) {
            UpdateDumpMode(BufferType, true, reply);
        } else {
            ShowDumpMenu(reply);
        }
    }
}

int32_t CameraDumpEvent(HdfSBuf *data, HdfSBuf *reply)
{
    CameraDumper::GetInstance().CameraHostDumpProcess(data, reply);
    return HDF_SUCCESS;
}

} // namespace OHOS::Camera
