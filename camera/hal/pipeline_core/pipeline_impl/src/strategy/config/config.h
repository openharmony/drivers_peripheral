/*
 * This is an automatically generated HDF config file. Do not modify it manually.
 */

#ifndef HCS_CONFIG_CONFIG_HEADER_H
#define HCS_CONFIG_CONFIG_HEADER_H

#include <stdint.h>

struct HdfConfigPipelineSpecsPortSpec {
    const char* name;
    const char* peer_port_name;
    const char* peer_port_node_name;
    uint8_t direction;
    uint8_t width;
    uint8_t height;
    uint8_t format;
    uint64_t usage;
    uint8_t need_allocation;
    uint8_t buffer_count;
};

struct HdfConfigPipelineSpecsNodeSpec {
    const char* name;
    const char* status;
    const char* stream_type;
    const struct HdfConfigPipelineSpecsPortSpec* portSpec;
    uint16_t portSpecSize;
};

struct HdfConfigPipelineSpecsPipelineSpec {
    const char* name;
    const struct HdfConfigPipelineSpecsNodeSpec* nodeSpec;
    uint16_t nodeSpecSize;
};

struct HdfConfigPipelineSpecsRoot {
    const char* module;
    const struct HdfConfigPipelineSpecsPipelineSpec* pipelineSpec;
    uint16_t pipelineSpecSize;
};

const struct HdfConfigPipelineSpecsRoot* HdfGetPipelineSpecsModuleConfigRoot(void);

#endif // HCS_CONFIG_CONFIG_HEADER_H
