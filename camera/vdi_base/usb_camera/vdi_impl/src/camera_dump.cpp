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
#include <cstdio>
#include "camera_dump.h"
#include "v1_0/vdi_types.h"
#include "camera.h"

using namespace std;

namespace OHOS::Camera {
const std::string DUMP_PATH = "/data/camera/";
constexpr uint32_t ARGS_MAX_NUM = 5;
constexpr uint32_t PATH_MAX_LEN = 200;
constexpr int32_t READ_DISKINFO_NUM = 6;
constexpr uint32_t MAX_USAGE_RATE = 70;
constexpr int32_t CHECK_DISKINFO_TIME_MS = 10000;
#define TITLEINFO_ARRAY_SIZE 200

const char *g_cameraDumpHelp =
    " Camera manager dump options:\n"
    "     -h: camera dump help\n"
    "     -m: start dump metadata\n"
    "     -b: start dump buffer\n"
    "     -e: exit all dump\n";

std::map<DumpType, bool> g_dumpInfoMap = {
    {MedataType, false},
    {BufferType, false}
};

struct DiskInfo {
    char diskName[100];
    uint32_t diskTotal;
    uint32_t diskUse;
    uint32_t canUse;
    uint32_t diskUsePer;
    char diskMountInfo[200];
};

CameraDumper::~CameraDumper()
{
    StopCheckDiskInfo();
}

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

    if (encodeType == VDI::Camera::V1_0::ENCODE_TYPE_JPEG) {
        ss << "]_" << GetCurrentLocalTimeStamp();
        ss >> fileName;
        fileName += ".jpeg";
    } else if (encodeType == VDI::Camera::V1_0::ENCODE_TYPE_H264) {
        ss << "]_" << GetCurrentLocalTimeStamp();
        ss >> fileName;
        fileName += "video.yuv";
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
    {
        std::lock_guard<std::mutex> l(dumpStateLock_);
        auto it = g_dumpInfoMap.find(type);
        if (it != g_dumpInfoMap.end()) {
            g_dumpInfoMap[type] = isDump;
            upRetStr += " set dump mode success!\n";
        }
    }

    if (reply != nullptr) {
        (void)HdfSbufWriteString(reply, upRetStr.c_str());
    }

    if (isDump) {
        StartCheckDiskInfo();
    } else {
        StopCheckDiskInfo();
    }
}

bool CameraDumper::IsDumpOpened(DumpType type)
{
    std::lock_guard<std::mutex> l(dumpStateLock_);
    return g_dumpInfoMap.find(type) != g_dumpInfoMap.end() && g_dumpInfoMap[type];
}

bool CameraDumper::SaveDataToFile(const char *fileName, const void *data, uint32_t size)
{
    std::stringstream mkdirCmd;
    mkdirCmd << "mkdir -p " << DUMP_PATH;
    system(mkdirCmd.str().c_str());

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
        } else if (strcmp(value, "-e") == 0) {
            UpdateDumpMode(BufferType, false, reply);
            UpdateDumpMode(MedataType, false, reply);
        } else {
            ShowDumpMenu(reply);
        }
    }
}

int32_t CameraDumpEvent(HdfSBuf *data, HdfSBuf *reply)
{
    CameraDumper& dumper = CameraDumper::GetInstance();
    dumper.CameraHostDumpProcess(data, reply);
    return HDF_SUCCESS;
}

void CameraDumper::CheckDiskInfo()
{
    DiskInfo diskInfo;
    auto ret = memset_s(&diskInfo, sizeof(DiskInfo), 0, sizeof(DiskInfo));
    if (ret != EOK) {
        CAMERA_LOGE("diskInfo memset failed!");
        return;
    }
    stringstream ss;
    ss << "df " << DUMP_PATH;

    FILE *fp = popen(ss.str().c_str(), "r");
    if (fp == NULL) {
        CAMERA_LOGE("popen failed, cmd : %{public}s", ss.str().c_str());
        return;
    }

    char titleInfo[TITLEINFO_ARRAY_SIZE] = {0};
    fgets(titleInfo, sizeof(titleInfo) / sizeof(titleInfo[0]) - 1, fp);
    int readNum = fscanf_s(fp, "%s %u %u %u %u%% %s\n", diskInfo.diskName, sizeof(diskInfo.diskName) - 1,
        &diskInfo.diskTotal, &diskInfo.diskUse, &diskInfo.canUse, &diskInfo.diskUsePer, diskInfo.diskMountInfo,
        sizeof(diskInfo.diskMountInfo) - 1);
    pclose(fp);

    if (readNum != READ_DISKINFO_NUM) {
        CAMERA_LOGW("readNum != READ_DISKINFO_NUM readNum: %{public}d", readNum);
        return;
    }

    if (diskInfo.diskUsePer >= MAX_USAGE_RATE) {
        std::lock_guard<std::mutex> l(dumpStateLock_);
        for (auto it = g_dumpInfoMap.begin(); it != g_dumpInfoMap.end(); it++) {
            it->second = false;
        }
        CAMERA_LOGD("readNum: %{public}d, diskName: %{public}s, diskUsePer: %{public}u%% diskMountInfo: %{public}s",
            readNum, diskInfo.diskName, diskInfo.diskUsePer, diskInfo.diskMountInfo);
    }
}

void CameraDumper::ThreadWorkFun()
{
    while (true) {
        CheckDiskInfo();

        std::unique_lock<std::mutex> l(terminateLock_);
        cv_.wait_for(l, std::chrono::milliseconds(CHECK_DISKINFO_TIME_MS),
            [this]() {
                return terminate_;
            }
        );

        if (terminate_) {
            break;
        }
    }
}

void CameraDumper::StartCheckDiskInfo()
{
    {
        std::unique_lock<std::mutex> l(terminateLock_);
        if (terminate_ == false) {
            CAMERA_LOGD("thread is already start");
            return;
        }
        terminate_ = false;
    }

    handleThread_ = std::make_unique<std::thread>(&CameraDumper::ThreadWorkFun, this);
}

void CameraDumper::StopCheckDiskInfo()
{
    {
        std::unique_lock<std::mutex> l(terminateLock_);
        if (terminate_ == true) {
            CAMERA_LOGW("thread is already stop");
            return;
        }
        terminate_ = true;
        cv_.notify_one();
    }
    if (handleThread_ != nullptr && handleThread_->joinable()) {
        handleThread_->join();
        handleThread_ = nullptr;
    }
}
} // namespace OHOS::Camera
