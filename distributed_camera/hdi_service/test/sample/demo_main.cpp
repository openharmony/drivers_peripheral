/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#include "dcamera_hdf_demo.h"
#include <cstdio>
#include <getopt.h>

#include "distributed_hardware_log.h"

namespace OHOS {
namespace DistributedHardware {

static void Usage(FILE* fp)
{
    fprintf(fp,
            "Options:\n"
            "-h | --help          Print this message\n"
            "-o | --offline       stream offline test\n"
            "-c | --capture       capture one picture\n"
            "-w | --set WB        Set white balance Cloudy\n"
            "-v | --video         capture Video of 10s\n"
            "-a | --Set AE        Set Auto exposure\n"
            "-e | --Set Metadeta  Set Metadata\n"
            "-f | --Set Flashlight        Set flashlight ON 5s OFF\n"
            "-q | --quit          stop preview and quit this app\n");
}

const static struct option LONG_OPTIONS[] = {
    {"help", no_argument, nullptr, 'h'}, {"capture", no_argument, nullptr, 'c'},
    {"WB", no_argument, nullptr, 'w'}, {"video", no_argument, nullptr, 'v'},
    {"quit", no_argument, nullptr, 'q'}, {"AE", no_argument, nullptr, 'a'},
    {"OL", no_argument, nullptr, 'o'}, {"flashlight", no_argument, nullptr, 'f'},
    {0, 0, 0, 0}
};

static int PutMenuAndGetChr(void)
{
    constexpr uint32_t inputCount = 50;
    int c = 0;
    char strs[inputCount];

    Usage(stdout);
    DHLOGI("pls input command(input -q exit this app)");
    fgets(strs, inputCount, stdin);

    for (uint32_t i = 0; i < inputCount; i++) {
        if (strs[i] != '-') {
            c = strs[i];
            break;
        }
    }

    return c;
}

static RetCode PreviewOn(int mode, const std::shared_ptr<DcameraHdfDemo>& mainDemo)
{
    RetCode rc = RC_OK;
    DHLOGI("main test: PreviewOn enter");

    rc = mainDemo->StartPreviewStream();
    if (rc != RC_OK) {
        DHLOGE("main test: PreviewOn StartPreviewStream error");
        return RC_ERROR;
    }
    DHLOGI("main test: StartPreviewStream enter");
    if (mode == 0) {
        rc = mainDemo->StartCaptureStream();
        if (rc != RC_OK) {
            DHLOGE("main test: PreviewOn StartCaptureStream error");
            return RC_ERROR;
        }
        DHLOGI("main test: StartCaptureStream enter");
    } else {
        rc = mainDemo->StartVideoStream();
        if (rc != RC_OK) {
            DHLOGE("main test: PreviewOn StartVideoStream error");
            return RC_ERROR;
        }
        DHLOGI("main test: StartVideoStream enter");
    }
    rc = mainDemo->CreateStream();
    if (rc != RC_OK) {
        DHLOGE("main test: CreateStream error");
        return RC_ERROR;
    }
    rc = mainDemo->CaptureON(STREAM_ID_PREVIEW, CAPTURE_ID_PREVIEW, CAPTURE_PREVIEW);
    if (rc != RC_OK) {
        DHLOGE("main test: PreviewOn mainDemo->CaptureON() preview error");
        return RC_ERROR;
    }

    DHLOGI("main test: PreviewOn exit");
    return RC_OK;
}

static void PreviewOff(const std::shared_ptr<DcameraHdfDemo>& mainDemo)
{
    DHLOGI("main test: PreviewOff enter");

    mainDemo->CaptureOff(CAPTURE_ID_PREVIEW, CAPTURE_PREVIEW);
    mainDemo->ReleaseAllStream();

    DHLOGI("main test: PreviewOff exit");
}

static void FlashLightTest(const std::shared_ptr<DcameraHdfDemo>& mainDemo)
{
    constexpr size_t delayTime = 5;

    PreviewOff(mainDemo);
    mainDemo->ReleaseCameraDevice();
    sleep(1);
    mainDemo->FlashlightOnOff(true);
    sleep(delayTime);
    mainDemo->FlashlightOnOff(false);
    mainDemo->InitCameraDevice();
    PreviewOn(0, mainDemo);
}

static void OfflineTest(const std::shared_ptr<DcameraHdfDemo>& mainDemo)
{
    RetCode rc = RC_OK;
    constexpr uint32_t delayTime = 5;
    PreviewOff(mainDemo);

    mainDemo->StartDualStreams(STREAM_ID_CAPTURE);
    mainDemo->CaptureOnDualStreams(STREAM_ID_CAPTURE);
    sleep(1);

    rc = mainDemo->StreamOffline(STREAM_ID_CAPTURE);
    if (rc != RC_OK) {
        DHLOGE("main test: mainDemo->StreamOffline error");
    }

    sleep(delayTime);
    mainDemo->InitCameraDevice();
    rc = PreviewOn(0, mainDemo);
    if (rc != RC_OK) {
        DHLOGE("main test: PreviewOn() error");
    }
}

static void CaptureTest(const std::shared_ptr<DcameraHdfDemo>& mainDemo)
{
    RetCode rc = RC_OK;
    constexpr size_t delayTime = 5;

    rc = mainDemo->CaptureON(STREAM_ID_CAPTURE, CAPTURE_ID_CAPTURE, CAPTURE_SNAPSHOT);
    if (rc != RC_OK) {
        DHLOGE("main test: mainDemo->CaptureON() capture error");
        return;
    }

    sleep(delayTime);
    rc = mainDemo->CaptureOff(CAPTURE_ID_CAPTURE, CAPTURE_SNAPSHOT);
    if (rc != RC_OK) {
        DHLOGE("main test: mainDemo->CaptureOff() capture error");
        return;
    }
    DHLOGI("main test: CaptureON success");
}

static void VideoTest(const std::shared_ptr<DcameraHdfDemo>& mainDemo)
{
    RetCode rc = RC_OK;
    constexpr size_t delayTime = 5;

    PreviewOff(mainDemo);
    mainDemo->StartDualStreams(STREAM_ID_VIDEO);
    mainDemo->CaptureOnDualStreams(STREAM_ID_VIDEO);

    sleep(delayTime);
    mainDemo->CaptureOff(CAPTURE_ID_PREVIEW, CAPTURE_PREVIEW);
    mainDemo->CaptureOff(CAPTURE_ID_VIDEO, CAPTURE_VIDEO);
    mainDemo->ReleaseAllStream();

    rc = PreviewOn(0, mainDemo);
    if (rc != RC_OK) {
        DHLOGE("main test: video PreviewOn() error please -q exit demo");
    }
}

static void SetAwb(const std::shared_ptr<DcameraHdfDemo>& mainDemo, int& awb)
{
    if (awb) {
        mainDemo->SetAwbMode(OHOS_CAMERA_AWB_MODE_INCANDESCENT);
    } else {
        mainDemo->SetAwbMode(OHOS_CAMERA_AWB_MODE_OFF);
    }
    awb = !awb;
}

static void ManuList(const std::shared_ptr<DcameraHdfDemo>& mainDemo, const int argc, char** argv)
{
    int idx, c;
    int awb = 1;
    const char *shortOptions = "h:cwvaeqof:";
    c = getopt_long(argc, argv, shortOptions, LONG_OPTIONS, &idx);
    while (1) {
        switch (c) {
            case 'h':
                c = PutMenuAndGetChr();
                break;
            case 'f':
                FlashLightTest(mainDemo);
                c = PutMenuAndGetChr();
                break;
            case 'o':
                OfflineTest(mainDemo);
                c = PutMenuAndGetChr();
                break;
            case 'c':
                CaptureTest(mainDemo);
                c = PutMenuAndGetChr();
                break;
            case 'w':
                SetAwb(mainDemo, awb);
                c = PutMenuAndGetChr();
                break;
            case 'a':
                mainDemo->SetAeExpo();
                c = PutMenuAndGetChr();
                break;
            case 'e':
                mainDemo->SetMetadata();
                c = PutMenuAndGetChr();
                break;
            case 'v':
                VideoTest(mainDemo);
                c = PutMenuAndGetChr();
                break;
            case 'q':
                PreviewOff(mainDemo);
                mainDemo->QuitDemo();
                return;
            default:
                DHLOGE("main test: command error please retry input command");
                c = PutMenuAndGetChr();
                break;
        }
    }
}

int main(int argc, char** argv)
{
    RetCode rc = RC_OK;
    std::cout << "dcamera hdi start" << std::endl;
    auto mainDemo = std::make_shared<DcameraHdfDemo>();
    rc = mainDemo->InitSensors();
    if (rc == RC_ERROR) {
        DHLOGE("main test: mainDemo->InitSensors() error");
        return -1;
    }
    std::cout << "dcamera InitSensors success" << std::endl;
    rc = mainDemo->InitCameraDevice();
    if (rc == RC_ERROR) {
        DHLOGE("main test: mainDemo->InitCameraDevice() error");
        return -1;
    }
    std::cout << "dcamera InitCameraDevice success" << std::endl;
    mainDemo->SetEnableResult();

    rc = PreviewOn(0, mainDemo);
    if (rc != RC_OK) {
        DHLOGE("main test: PreviewOn() error demo exit");
        return -1;
    }
    std::cout << "dcamera PreviewOn success" << std::endl;
    std::cout << "dcamera ManuList start" << std::endl;
    ManuList(mainDemo, argc, argv);
    std::cout << "dcamera hdi end" << std::endl;
    return RC_OK;
}
}
} // namespace OHOS::DistributedHardware

int main(int argc, char** argv)
{
    OHOS::DistributedHardware::main(argc, argv);

    return 0;
}