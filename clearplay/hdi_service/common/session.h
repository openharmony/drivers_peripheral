#ifndef CLEARPLAY_SESSION_H
#define CLEARPLAY_SESSION_H

#include <hdf_base.h>
#include <hdi_base.h>
#include <vector>
#include "v1_0/media_key_system_types.h"

namespace OHOS {
namespace HDI {
namespace Drm {
namespace V1_0 {

class Session : public RefBase {
public:
    explicit Session(){}
    virtual ~Session(){}
    int32_t getKeyRequest(const std::vector<uint8_t>& indexInfo,
        const std::string& mimeType, LicenseType keyType, std::map<std::string, std::string> optionalData, std::vector<uint8_t>* keyRequest);
    int32_t setKeyIdAndKeyValue(const std::vector<uint8_t>& keyId, const std::vector<uint8_t>& keyValue);
    int32_t getKeyValueByKeyId(const std::vector<uint8_t>& keyId, std::vector<uint8_t>& keyValue);
    std::vector<std::pair<std::vector<uint8_t>, std::vector<uint8_t>>> keyIdAndKeyValue_;
};

} // V1_0
} // Drm
} // HDI
} // OHOS
#endif // CLEARPLAY_SESSION_H