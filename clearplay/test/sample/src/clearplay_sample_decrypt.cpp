/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include <iostream>
#include <stdio.h>
#include <hdf_base.h>
#include <hdf_log.h>
#include <ashmem.h>
#include <memory.h>
#include <sys/mman.h>

#include "v1_0/media_key_system_factory_service.h"
#include "mime_type.h"
#include "byte_show.h"
#include "securec.h"

using namespace OHOS;
using namespace OHOS::HDI::Drm::V1_0;

#define HDF_LOG_TAG clearplay_sample_decrypt

int main(int argc, char *argv[])
{
    // create key system factory
    sptr<OHOS::HDI::Drm::V1_0::IMediaKeySystemFactory> media_key_system_factory = new MediaKeySystemFactoryService();
    
    // CreateMediaKeySystem
    sptr<OHOS::HDI::Drm::V1_0::IMediaKeySystem> media_key_system;
    media_key_system_factory->CreateMediaKeySystem(media_key_system);
    printf("CreateMediaKeySystem\n");

    // CreateMediaKeySession
    printf("\ntest CreateMediaKeySession\n");
    sptr<OHOS::HDI::Drm::V1_0::IMediaKeySession> key_session;
    media_key_system->CreateMediaKeySession(SECURE_UNKNOWN, key_session);
    printf("CreateMediaKeySession\n");

    // ProcessLicenseResponse
    printf("\ntest ProcessLicenseResponse\n");
    std::string responseString = "key1:1234567812345678";
    std::vector<uint8_t> response(responseString.begin(), responseString.end());
    std::vector<uint8_t> keyId;
    key_session->ProcessLicenseResponse(response, keyId);
    printf("keyid: %s, expect: key1\n", keyId.data());

    // GetMediaDecryptModule
    sptr<OHOS::HDI::Drm::V1_0::IMediaDecryptModule> decryptModule;
    key_session->GetMediaDecryptModule(decryptModule);

    // DecryptData
    printf("\nDecryptData\n");
    CryptoInfo info;
    int32_t ret = HDF_FAILURE;
    info.type = ALGTYPE_AES_CBC;
    info.keyId = keyId;
    info.iv = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
    info.pattern.encryptBlocks = 0;
    info.pattern.skipBlocks = 0;
    SubSample subSample;
    subSample.clearHeaderLen = 0;
    subSample.payLoadLen = 16;
    info.subSamples.push_back(subSample);
    DrmBuffer srcBuffer;
    memset_s(&srcBuffer, sizeof(DrmBuffer),0x0, sizeof(DrmBuffer));
    DrmBuffer dstBuffer;
    memset_s(&dstBuffer, sizeof(DrmBuffer), 0x0, sizeof(DrmBuffer));

    std::vector<uint8_t> testData = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
    int srcFd = AshmemCreate("clearPlaySrcData", sizeof(testData));
    int dstFd = AshmemCreate("clearPlayDstData", sizeof(testData));
    srcBuffer.fd = srcFd;
    srcBuffer.bufferLen = sizeof(testData);
    dstBuffer.fd = dstFd;
    dstBuffer.bufferLen = sizeof(testData);
    uint8_t *srcData =
        (uint8_t *)mmap(nullptr, srcBuffer.bufferLen, PROT_READ | PROT_WRITE, MAP_SHARED, srcBuffer.fd, 0);
    ret = memcpy_s(srcData, sizeof(testData), &testData, sizeof(testData));
    if (ret != 0) {
        HDF_LOGE("%{public}s: memcpy_s faild", __func__);
        return ret;
    }
    (void)munmap(srcData, srcBuffer.bufferLen);

    decryptModule->DecryptMediaData(false, info, srcBuffer, dstBuffer);

    uint8_t *dstData =
        (uint8_t *)mmap(nullptr, dstBuffer.bufferLen, PROT_READ | PROT_WRITE, MAP_SHARED, dstBuffer.fd, 0);
    ByteShow("clearplay decrypt", dstData, dstBuffer.bufferLen);
    (void)munmap(dstData, dstBuffer.bufferLen);
    printf("\n\n");
    media_key_system->Destroy();
    printf("Destroy\n");
    return 0;
}