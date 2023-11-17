#include <hdf_base.h>
#include <hdf_log.h>
#include "clearplay_uuid.h"

#define HDF_LOG_TAG    data_parse

namespace OHOS {
namespace HDI {
namespace Drm {
namespace V1_0 {

bool IsClearPlayUuid(const std::string& uuid) {
    return uuid == clearPlayUuid;
}

} // V1_0
} // Drm
} // HDI
} // OHOS