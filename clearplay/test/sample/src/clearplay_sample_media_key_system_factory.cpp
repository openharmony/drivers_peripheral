#include <iostream>
#include <stdio.h>
#include <hdf_base.h>
#include <hdf_log.h>

#include "clearplay_sample_media_key_system_factory.h"
#include "v1_0/media_key_system_factory_service.h"
#include "mime_type.h"

using namespace OHOS;
using namespace OHOS::HDI::Drm::V1_0;

#define HDF_LOG_TAG clearplay_sample_media_key_system_factory

int main(int argc, char *argv[])
{
    // data init
    std::string clearPlayUuid = "E79628B6406A6724DCD5A1DA50B53E80";
    bool isSupported = false;

    // create key system factory
    sptr<OHOS::HDI::Drm::V1_0::IMediaKeySystemFactory> media_key_system_factory = new MediaKeySystemFactoryService();

    // IsMediaKeySystemSupported case 1
    media_key_system_factory->IsMediaKeySystemSupported(clearPlayUuid, isoVideoMimeType, SECURE_UNKNOWN, isSupported);
    printf("IsMediaKeySystemSupported: %d, expect 1\n", isSupported);
    // IsMediaKeySystemSupported case 2
    clearPlayUuid = "E79628B6406A6724DCD5A1DA50B53E81"; // wrong uuid
    media_key_system_factory->IsMediaKeySystemSupported(clearPlayUuid, isoVideoMimeType, SECURE_UNKNOWN, isSupported);
    printf("IsMediaKeySystemSupported: %d, expect 0\n", isSupported);

    // CreateMediaKeySystem
    sptr<OHOS::HDI::Drm::V1_0::IMediaKeySystem> media_key_system;
    media_key_system_factory->CreateMediaKeySystem(media_key_system);
    printf("CreateMediaKeySystem\n");

    // MediaKeySystem Destroy
    media_key_system->Destroy();
    printf("Destroy\n");
    return 0;
}