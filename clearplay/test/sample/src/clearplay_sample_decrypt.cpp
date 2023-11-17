#include <iostream>
#include <stdio.h>
#include <hdf_base.h>
#include <hdf_log.h>
#include <ashmem.h>
#include <memory.h>
#include <sys/mman.h>

#include "clearplay_sample_decrypt.h"
#include "v1_0/media_key_system_factory_service.h"
#include "mime_type.h"
#include "byte_show.h"

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
    info.type = ALGTYPE_AES_CBC;
    info.keyId = keyId;
    info.iv = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };
    info.pattern.encryptBlocks = 0;
    info.pattern.skipBlocks = 0;
    SubSample subSample;
    subSample.clearHeaderLen = 0;
    subSample.payLoadLen = 16;
    info.subSamples.push_back(subSample);
    DrmBuffer srcBuffer;
    memset(&srcBuffer, 0x0, sizeof(DrmBuffer));
    DrmBuffer dstBuffer;
    memset(&dstBuffer, 0x0, sizeof(DrmBuffer));

    std::vector<uint8_t> testData = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };
    int srcFd = AshmemCreate("clearPlaySrcData", sizeof(testData));
    int dstFd = AshmemCreate("clearPlayDstData", sizeof(testData));
    srcBuffer.fd = srcFd;
    srcBuffer.bufferLen = sizeof(testData);
    dstBuffer.fd = dstFd;
    dstBuffer.bufferLen = sizeof(testData);
    uint8_t *srcData = (uint8_t *)mmap(nullptr, srcBuffer.bufferLen, PROT_READ | PROT_WRITE, MAP_SHARED, srcBuffer.fd, 0);
    memcpy(srcData, &testData, sizeof(testData));
    (void)munmap(srcData, srcBuffer.bufferLen);

    decryptModule->DecryptMediaData(false, info, srcBuffer, dstBuffer);

    uint8_t *dstData = (uint8_t *)mmap(nullptr, dstBuffer.bufferLen, PROT_READ | PROT_WRITE, MAP_SHARED, dstBuffer.fd, 0);
    ByteShow("clearplay decrypt", dstData, dstBuffer.bufferLen);
    (void)munmap(dstData, dstBuffer.bufferLen);
    printf("\n\n");
    media_key_system->Destroy();
    printf("Destroy\n");
    return 0;
}