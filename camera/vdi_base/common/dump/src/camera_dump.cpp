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

#include "camera_dump.h"

#include <sys/time.h>
#include <fstream>
#include <sstream>
#include <cstdio>
#include <iostream>
#include <cstdlib>
#include <regex>

#include "camera.h"
#include "v1_0/vdi_types.h"

using namespace std;

namespace OHOS::Camera {
const std::string DUMP_PATH = "/data/local/tmp/";
const std::string DUMP_CONFIG_PATH = "/data/local/tmp/dump.config";
constexpr uint32_t ARGS_MAX_NUM = 5;
constexpr uint32_t MAX_USAGE_RATE = 70;
constexpr int32_t CHECK_DISKINFO_TIME_MS = 10000;
const uint32_t TITLEINFO_ARRAY_SIZE = 200;

const char *g_cameraDumpHelp =
    " Camera manager dump options:\n"
    "     -h: camera dump help\n"
    "     -m: start dump metadata\n"
    "     -b: start dump buffer\n"
    "     -o: start dump start\n"
    "     -e: exit all dump\n";

std::map<DumpType, bool> g_dumpInfoMap = {
    {MedataType, false},
    {BufferType, false},
    {OpenType, false}
};

std::map<std::string, std::string> g_dumpToolMap = {
    {ENABLE_DQ_BUFFER_DUMP, "false"},
    {ENABLE_UVC_NODE, "false"},
    {ENABLE_UVC_NODE_CONVERTED, "false"},
    {ENABLE_EXIF_NODE_CONVERTED, "false"},
    {ENABLE_FACE_NODE_CONVERTED, "false"},
    {ENABLE_FORK_NODE_CONVERTED, "false"},
    {ENABLE_RKFACE_NODE_CONVERTED, "false"},
    {ENABLE_RKEXIF_NODE_CONVERTED, "false"},
    {ENABLE_CODEC_NODE_CONVERTED, "false"},
    {ENABLE_RKCODEC_NODE_CONVERTED, "false"},
    {ENABLE_STREAM_TUNNEL, "false"},
    {ENABLE_METADATA, "false"},
    {PREVIEW_INTERVAL, "1"},
    {CAPTURE_INTERVAL, "1"}
};

CameraDumper::~CameraDumper()
{
    StopCheckDiskInfo();
}

bool CameraDumper::DumpStart()
{
    if (!IsDumpOpened(OpenType)) {
        return false;
    }
    std::stringstream mkdirCmd;
    mkdirCmd << "mkdir -p " << DUMP_PATH;
    system(mkdirCmd.str().c_str());

    ReadDumpConfig();
    return true;
}

bool CameraDumper::ReadDumpConfig()
{
    std::stringstream ss;
    ss << DUMP_CONFIG_PATH;
    std::ifstream ifs;
    ifs.open(ss.str(), std::ios::in);
    if (!ifs) {
        CAMERA_LOGE("open dump config file <%{public}s> failed, error: %{public}s",
            ss.str().c_str(), std::strerror(errno));
        return false;
    }

    std::string str;
    while (!ifs.eof()) {
        if (ifs >> str) {
            istringstream istr(str);
            std::string strTemp;
            vector<std::string> strVector;
            while (getline(istr, strTemp, '=')) {
                strVector.push_back(strTemp);
            }
            g_dumpToolMap[strVector[0]] = strVector[1];
        }
    }

    ifs.close();
    return true;
}

bool CameraDumper::IsDumpCommandOpened(std::string type)
{
    std::lock_guard<std::mutex> l(dumpStateLock_);
    if (g_dumpToolMap.find(type) != g_dumpToolMap.end() && g_dumpToolMap[type] == "true") {
        return true;
    }
    return false;
}

bool CameraDumper::DumpBuffer(std::string name, std::string type, const std::shared_ptr<IBuffer>& buffer,
    uint32_t width, uint32_t height)
{
    if (!IsDumpOpened(OpenType) || !IsDumpCommandOpened(type) || (buffer == nullptr)) {
        return false;
    }

    uint32_t defaultWidth = (width == 0) ? buffer->GetCurWidth() : width;
    uint32_t defaultHeight = (height == 0) ? buffer->GetCurHeight() : height;
    void* srcAddr = buffer->GetIsValidDataInSurfaceBuffer() ? buffer->GetSuffaceBufferAddr() : buffer->GetVirAddress();
    uint32_t size = buffer->GetIsValidDataInSurfaceBuffer() ? buffer->GetSuffaceBufferSize() : buffer->GetSize();
    const std::string DqBufferName = "DQBuffer";
    if (name != DqBufferName) {
        size = buffer->GetEsFrameInfo().size > 0 ? buffer->GetEsFrameInfo().size : size;
    }

    std::stringstream ss;
    std::string fileName;
    ss << name.c_str() << "_captureId[" << buffer->GetCaptureId() << "]_streamId[" << buffer->GetStreamId() <<
        "]_width[" << defaultWidth << "]_height[" << defaultHeight;

    int32_t previewInterval = 1;
    std::istringstream ssPreview(g_dumpToolMap[PREVIEW_INTERVAL]);
    ssPreview >> previewInterval;

    int32_t captureInterval = 1;
    std::istringstream ssVideo(g_dumpToolMap[CAPTURE_INTERVAL]);
    ssVideo >> captureInterval;

    ++dumpCount_;
    if (buffer->GetEncodeType() == VDI::Camera::V1_0::ENCODE_TYPE_JPEG) {
        if (dumpCount_ % captureInterval != 0) {
            return true;
        }
        ss << "]_" << GetCurrentLocalTimeStamp();
        ss >> fileName;
        fileName += ".jpeg";
    } else if (buffer->GetEncodeType() == VDI::Camera::V1_0::ENCODE_TYPE_H264) {
#ifdef CAMERA_BUILT_ON_USB
        ss << "]_" << GetCurrentLocalTimeStamp();
        ss >> fileName;
        fileName += "_umpVideo.yuv";
#else
        fileName += "dumpVideo.h264";
#endif
    } else {
        if (dumpCount_ % previewInterval != 0) {
            return true;
        }

        ss << "]_" << GetCurrentLocalTimeStamp();
        ss >> fileName;
        fileName += ".yuv";
    }
    return SaveDataToFile(fileName.c_str(), srcAddr, size);
}

bool CameraDumper::DumpMetadata(std::string name, std::string type,
    const std::shared_ptr<CameraMetadata>& metadata)
{
    if (metadata == nullptr) {
        CAMERA_LOGE("metadata is nullptr");
        return false;
    }

    if (!IsDumpOpened(OpenType) || !IsDumpCommandOpened(type)) {
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
    ss << GetCurrentLocalTimeStamp() << "_" << name << ".meta";

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
    if (g_dumpInfoMap.find(type) != g_dumpInfoMap.end() && g_dumpInfoMap[type]) {
        return true;
    }
    return false;
}

bool CameraDumper::SaveDataToFile(const char *fileName, const void *data, uint32_t size)
{
    CAMERA_LOGI("save dump file <%{public}s> begin, size: %{public}d", fileName, size);
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
        } else if (strcmp(value, "-o") == 0) {
            UpdateDumpMode(OpenType, true, reply);
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
    stringstream ss;
    ss << "df " << DUMP_PATH;

    FILE *fp = popen(ss.str().c_str(), "r");
    if (fp == NULL) {
        CAMERA_LOGE("popen failed, cmd : %{public}s", ss.str().c_str());
        return;
    }

    char titleInfo[TITLEINFO_ARRAY_SIZE] = {0};
    char resultInfo[TITLEINFO_ARRAY_SIZE] = {0};
    fgets(titleInfo, sizeof(titleInfo) / sizeof(titleInfo[0]) - 1, fp);
    fgets(resultInfo, sizeof(resultInfo) / sizeof(resultInfo[0]) - 1, fp);

    pclose(fp);

    std::string diskInfoStr(resultInfo);
    istringstream str(diskInfoStr);
    string out;
    std::vector<std::string> infos;

    while (str >> out) {
        infos.push_back(out);
    }

    std::string userPerStr = infos[4].substr(0, infos[4].length() - 1);
    uint32_t usePer = std::atoi(userPerStr.c_str());
    if (usePer >= MAX_USAGE_RATE) {
        CAMERA_LOGE("dump use disk over the limit, stop dump");
        std::lock_guard<std::mutex> l(dumpStateLock_);
        for (auto it = g_dumpInfoMap.begin(); it != g_dumpInfoMap.end(); it++) {
            it->second = false;
        }
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

    handleThread_ = std::make_unique<std::thread>([this]{ this->ThreadWorkFun(); });
}

void CameraDumper::StopCheckDiskInfo()
{
    {
        std::unique_lock<std::mutex> l(terminateLock_);
        if (terminate_ == true) {
            CAMERA_LOGD("thread is already stop");
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

CameraDumper& CameraDumper::GetInstance()
{
    static CameraDumper instance_;
    return instance_;
}
} // namespace OHOS::Camera
