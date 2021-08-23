/*
 * This is an automatically generated HDF config file. Do not modify it manually.
 */

#ifndef HCS_CONFIG_PARAMS_HEADER_H
#define HCS_CONFIG_PARAMS_HEADER_H

#include <stdint.h>

struct HdfConfigStreamInfo {
    uint8_t id;
    const char* name;
};

struct HdfConfigSceneInfo {
    uint8_t id;
    const char* name;
};

struct HdfConfigRoot {
    const char* module;
    const struct HdfConfigStreamInfo* streamInfo;
    uint16_t streamInfoSize;
    const struct HdfConfigSceneInfo* sceneInfo;
    uint16_t sceneInfoSize;
};

const struct HdfConfigRoot* HdfGetModuleConfigRoot(void);

#endif // HCS_CONFIG_PARAMS_HEADER_H
