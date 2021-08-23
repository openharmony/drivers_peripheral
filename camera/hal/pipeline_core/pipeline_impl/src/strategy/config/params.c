/*
 * This is an automatically generated HDF config file. Do not modify it manually.
 */

#include "params.h"

static const struct HdfConfigStreamInfo g_hdfConfigStreamInfo[];

static const struct HdfConfigSceneInfo g_hdfConfigSceneInfo[];

static const struct HdfConfigStreamInfo g_hdfConfigStreamInfo[] = {
    [0] = {
        .id = 0x0,
        .name = "preview",
    },
    [1] = {
        .id = 0x1,
        .name = "video",
    },
    [2] = {
        .id = 0x2,
        .name = "snapshot",
    },
};

static const struct HdfConfigSceneInfo g_hdfConfigSceneInfo[] = {
    [0] = {
        .id = 0x0,
        .name = "normal",
    },
};

static const struct HdfConfigRoot g_hdfConfigModuleRoot = {
    .module = "",
    .streamInfo = g_hdfConfigStreamInfo,
    .streamInfoSize = 3,
    .sceneInfo = g_hdfConfigSceneInfo,
    .sceneInfoSize = 1,
};

const struct HdfConfigRoot* HdfGetModuleConfigRoot(void)
{
    return &g_hdfConfigModuleRoot;
}
