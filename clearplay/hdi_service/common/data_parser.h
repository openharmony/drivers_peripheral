#ifndef CLEARPLAY_DATAPARSER_H
#define CLEARPLAY_DATAPARSER_H

#include <hdf_base.h>
#include <hdi_base.h>
#include "v1_0/media_key_system_types.h"

namespace OHOS {
namespace HDI {
namespace Drm {
namespace V1_0 {

const size_t keyIdSize = 16;
const size_t systemIdSize = 16;

int32_t ParsePssh(const std::vector<uint8_t>& initData, std::vector<std::vector<uint8_t>>& keyIds);

int32_t generateRequest(const LicenseType keyType, const std::vector<std::vector<uint8_t>>& keyIds, std::string* request);

int32_t findSubVector(const std::vector<uint8_t>& main, const std::vector<uint8_t>& sub);

} // V1_0
} // Drm
} // HDI
} // OHOS
#endif // CLEARPLAY_DATAPARSER_H