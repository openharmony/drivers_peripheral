#ifndef IHUKSTYPES_H
#define IHUKSTYPES_H

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

struct HuksBlob {
    uint8_t* data;
    uint32_t dataLen;
};

struct HuksParamSet {
    uint8_t* data;
    uint32_t dataLen;
};

enum HuksChipsetPlatformDecryptScene {
    HUKS_CHIPSET_PLATFORM_DECRYPT_SCENCE_TA_TO_TA = 1,
};
#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif // IHUKSTYPES_H