#include <iostream>
#include <stdio.h>
#include <hdf_base.h>
#include <hdf_log.h>

#include "clearplay_sample_media_key_system.h"
#include "v1_0/media_key_system_factory_service.h"
#include "mime_type.h"

using namespace OHOS;
using namespace OHOS::HDI::Drm::V1_0;

#define HDF_LOG_TAG clearplay_sample_media_key_system

int main(int argc, char *argv[])
{
    // data init
    std::vector<uint8_t> inputValue;
    std::vector<uint8_t> outputValue;
    std::map<std::string, std::string> metric;
    SecurityLevel level = SECURE_UNKNOWN;
    sptr<OHOS::HDI::Drm::V1_0::IMediaKeySession> key_session_1;
    sptr<OHOS::HDI::Drm::V1_0::IMediaKeySession> key_session_2;
    sptr<OHOS::HDI::Drm::V1_0::IMediaKeySession> key_session_3;
    sptr<OHOS::HDI::Drm::V1_0::IMediaKeySession> key_session_4;

    // create key system factory
    sptr<OHOS::HDI::Drm::V1_0::IMediaKeySystemFactory> media_key_system_factory = new MediaKeySystemFactoryService();

    // CreateMediaKeySystem
    sptr<OHOS::HDI::Drm::V1_0::IMediaKeySystem> media_key_system;
    media_key_system_factory->CreateMediaKeySystem(media_key_system);
    printf("CreateMediaKeySystem\n");

    // set and get configuration
    printf("\ntest set and get configuration\n");
    inputValue.push_back('v');
    inputValue.push_back('a');
    inputValue.push_back('l');
    inputValue.push_back('u');
    inputValue.push_back('e');
    media_key_system->SetConfigurationByteArray("name1", inputValue);
    media_key_system->SetConfigurationByteArray("name2", inputValue);
    media_key_system->SetConfigurationByteArray("name3", inputValue);

    media_key_system->GetConfigurationByteArray("name1", outputValue);
    printf("outputValue: %s, expect: value\n", outputValue.data());

    // GetMetric
    printf("\ntest GetMetric\n");
    media_key_system->GetMetrics(metric);
    for (auto& pair:metric) {
        printf("key: %s, value: %s\n", pair.first.c_str(), pair.second.c_str());
    }

    // GetSecurityLevel
    printf("result of GetSecurityLevel: %d, expect: -1\n", media_key_system->GetMaxSecurityLevel(level));

    // CreateMediaKeySession
    /*
    SECURE_UNKNOWN = 0,
    SW_SECURE_CRYPTO = 1,
    SW_SECURE_DECODE = 2,
    HW_SECURE_CRYPTO = 3,
    HW_SECURE_DECODE = 4,
    HW_SECURE_ALL = 5,
    */
    printf("\ntest CreateMediaKeySession\n");
    media_key_system->CreateMediaKeySession(SW_SECURE_CRYPTO, key_session_1);
    media_key_system->CreateMediaKeySession(SW_SECURE_DECODE, key_session_2);
    media_key_system->CreateMediaKeySession(HW_SECURE_CRYPTO, key_session_3);
    media_key_system->CreateMediaKeySession(HW_SECURE_DECODE, key_session_4);
    printf("CreateMediaKeySession\n");

    // GetMaxSecurityLevel
    printf("\ntest GetMaxSecurityLevel\n");
    media_key_system->GetMaxSecurityLevel(level);
    printf("level: %d, expect: 4\n", level);
    key_session_4->Destroy();
    media_key_system->GetMaxSecurityLevel(level);
    printf("level: %d, expect: 3\n", level);

    // GenerateKeySystemRequest
    std::vector<uint8_t> request;
    std::string defaultUrl;
    media_key_system->GenerateKeySystemRequest(defaultUrl, request);
    // std::string requestString(request.begin(), request.end());
    printf("request: %s\n", request.data());

    // ProcessKeySystemResponse
    media_key_system->ProcessKeySystemResponse(request);

    // MediaKeySystem Destroy
    media_key_system->Destroy();
    printf("Destroy\n");
    return 0;
}