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

#ifndef HDI_CAMERA_DUMP_H
#define HDI_CAMERA_DUMP_H

#include <string>
#include <map>
#include <thread>
#include <mutex>
#include <condition_variable>
#include "camera_metadata_operator.h"
#include "camera_metadata_info.h"
#include "devhost_dump_reg.h"
#include "hdf_sbuf.h"
#include "ibuffer.h"
#include <iostream>

namespace OHOS::Camera {
enum DumpType {
    MedataType,
    BufferType,
    OpenType
};

const std::string ENABLE_DQ_BUFFER_DUMP = "enableDQBufDump";
const std::string ENABLE_UVC_NODE = "enableUVCNodeBufferDump";
const std::string ENABLE_UVC_NODE_CONVERTED = "enableUVCNodeConvertedBufferDump";
const std::string ENABLE_EXIF_NODE_CONVERTED = "enableExifNodeConvertedBufferDump";
const std::string ENABLE_FACE_NODE_CONVERTED = "enableFaceNodeConvertedBufferDump";
const std::string ENABLE_FORK_NODE_CONVERTED = "enableForkNodeConvertedBufferDump";
const std::string ENABLE_RKFACE_NODE_CONVERTED = "enableRKFaceNodeConvertedBufferDump";
const std::string ENABLE_RKEXIF_NODE_CONVERTED = "enableRKExifNodeConvertedBufferDump";
const std::string ENABLE_CODEC_NODE_CONVERTED = "enableCodecNodeConvertedBufferDump";
const std::string ENABLE_RKCODEC_NODE_CONVERTED = "enableRKCodecNodeConvertedBufferDump";
const std::string ENABLE_STREAM_TUNNEL = "enableSreamTunnelBufferDump";
const std::string ENABLE_METADATA = "enableMetadataDump";
const std::string PREVIEW_INTERVAL = "previewInterval";
const std::string CAPTURE_INTERVAL = "captureInterval";

class CameraDumper {
public:
    ~CameraDumper ();
    bool DumpBuffer(std::string name, std::string type, const std::shared_ptr<IBuffer>& buffer,
        uint32_t width = 0, uint32_t height = 0);
    bool DumpStart();
    bool ReadDumpConfig();
    bool IsDumpCommandOpened(std::string type);
    bool DumpMetadata(std::string name, std::string type, const std::shared_ptr<CameraMetadata>& metadata);
    void ShowDumpMenu(struct HdfSBuf *reply);
    void CameraHostDumpProcess(struct HdfSBuf *data, struct HdfSBuf *reply);
    static CameraDumper& GetInstance();

private:
    CameraDumper() {}
    bool IsDumpOpened(DumpType type);
    uint64_t GetCurrentLocalTimeStamp();
    void UpdateDumpMode(DumpType type, bool isDump, struct HdfSBuf *reply);
    bool SaveDataToFile(const char *fileName, const void *data, uint32_t size);
    void CheckDiskInfo();
    void ThreadWorkFun();
    void StartCheckDiskInfo();
    void StopCheckDiskInfo();

private:
    std::mutex dumpStateLock_;
    std::condition_variable cv_;
    std::mutex terminateLock_;
    bool terminate_ = true;
    std::unique_ptr<std::thread> handleThread_ = nullptr;
    int32_t dumpCount_ = 0;
};

int32_t CameraDumpEvent(struct HdfSBuf *data, struct HdfSBuf *reply);

} // OHOS::Camera

#endif // HDI_CAMERA_DUMP_H
