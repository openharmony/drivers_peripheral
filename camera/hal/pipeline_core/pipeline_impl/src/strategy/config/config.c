/*
 * This is an automatically generated HDF config file. Do not modify it manually.
 */

#include "config.h"

static const struct HdfConfigPipelineSpecsPipelineSpec g_hdfConfigPipelineSpec[];

static const struct HdfConfigPipelineSpecsPortSpec g_hdfConfigPortSpec[];

static const struct HdfConfigPipelineSpecsPortSpec g_hdfConfigPortSpec2[];

static const struct HdfConfigPipelineSpecsPortSpec g_hdfConfigPortSpec3[];

static const struct HdfConfigPipelineSpecsPortSpec g_hdfConfigPortSpec4[];

static const struct HdfConfigPipelineSpecsNodeSpec g_hdfConfigNodeSpec[];

static const struct HdfConfigPipelineSpecsPortSpec g_hdfConfigPortSpec5[];

static const struct HdfConfigPipelineSpecsPortSpec g_hdfConfigPortSpec6[];

static const struct HdfConfigPipelineSpecsPortSpec g_hdfConfigPortSpec7[];

static const struct HdfConfigPipelineSpecsPortSpec g_hdfConfigPortSpec8[];

static const struct HdfConfigPipelineSpecsPortSpec g_hdfConfigPortSpec9[];

static const struct HdfConfigPipelineSpecsNodeSpec g_hdfConfigNodeSpec2[];

static const struct HdfConfigPipelineSpecsPortSpec g_hdfConfigPortSpec10[];

static const struct HdfConfigPipelineSpecsPortSpec g_hdfConfigPortSpec11[];

static const struct HdfConfigPipelineSpecsPortSpec g_hdfConfigPortSpec12[];

static const struct HdfConfigPipelineSpecsPortSpec g_hdfConfigPortSpec13[];

static const struct HdfConfigPipelineSpecsPortSpec g_hdfConfigPortSpec14[];

static const struct HdfConfigPipelineSpecsPortSpec g_hdfConfigPortSpec15[];

static const struct HdfConfigPipelineSpecsNodeSpec g_hdfConfigNodeSpec3[];

static const struct HdfConfigPipelineSpecsPortSpec g_hdfConfigPortSpec16[];

static const struct HdfConfigPipelineSpecsPortSpec g_hdfConfigPortSpec17[];

static const struct HdfConfigPipelineSpecsPortSpec g_hdfConfigPortSpec18[];

static const struct HdfConfigPipelineSpecsPortSpec g_hdfConfigPortSpec19[];

static const struct HdfConfigPipelineSpecsPortSpec g_hdfConfigPortSpec20[];

static const struct HdfConfigPipelineSpecsNodeSpec g_hdfConfigNodeSpec4[];

static const struct HdfConfigPipelineSpecsPortSpec g_hdfConfigPortSpec21[];

static const struct HdfConfigPipelineSpecsPortSpec g_hdfConfigPortSpec22[];

static const struct HdfConfigPipelineSpecsPortSpec g_hdfConfigPortSpec23[];

static const struct HdfConfigPipelineSpecsPortSpec g_hdfConfigPortSpec24[];

static const struct HdfConfigPipelineSpecsPortSpec g_hdfConfigPortSpec25[];

static const struct HdfConfigPipelineSpecsNodeSpec g_hdfConfigNodeSpec5[];

static const struct HdfConfigPipelineSpecsPipelineSpec g_hdfConfigPipelineSpec[] = {
    [0] = {
        .name = "normal_preview",
        .nodeSpec = g_hdfConfigNodeSpec,
        .nodeSpecSize = 4,
    },
    [1] = {
        .name = "normal_snapshot",
        .nodeSpec = g_hdfConfigNodeSpec2,
        .nodeSpecSize = 5,
    },
    [2] = {
        .name = "normal_preview_snapshot",
        .nodeSpec = g_hdfConfigNodeSpec3,
        .nodeSpecSize = 6,
    },
    [3] = {
        .name = "normal_preview_video",
        .nodeSpec = g_hdfConfigNodeSpec4,
        .nodeSpecSize = 5,
    },
    [4] = {
        .name = "normal_preview_preview",
        .nodeSpec = g_hdfConfigNodeSpec5,
        .nodeSpecSize = 5,
    },
};

static const struct HdfConfigPipelineSpecsPortSpec g_hdfConfigPortSpec[] = {
    [0] = {
        .name = "out0",
        .peer_port_name = "in0",
        .peer_port_node_name = "vi#0",
        .direction = 0x1,
        .width = 0x0,
        .height = 0x0,
        .format = 0x0,
        .usage = 0x10000000000000,
        .need_allocation = 0x0,
        .buffer_count = 0x0,
    },
};

static const struct HdfConfigPipelineSpecsPortSpec g_hdfConfigPortSpec2[] = {
    [0] = {
        .name = "in0",
        .peer_port_name = "out0",
        .peer_port_node_name = "sensor#0",
        .direction = 0x0,
        .width = 0x0,
        .height = 0x0,
        .format = 0x0,
        .usage = 0x10000000000000,
        .need_allocation = 0x0,
        .buffer_count = 0x0,
    },
    [1] = {
        .name = "out0",
        .peer_port_name = "in0",
        .peer_port_node_name = "vpss#0",
        .direction = 0x1,
        .width = 0x0,
        .height = 0x0,
        .format = 0x0,
        .usage = 0x10000000000000,
        .need_allocation = 0x0,
        .buffer_count = 0x0,
    },
};

static const struct HdfConfigPipelineSpecsPortSpec g_hdfConfigPortSpec3[] = {
    [0] = {
        .name = "in0",
        .peer_port_name = "out0",
        .peer_port_node_name = "vi#0",
        .direction = 0x0,
        .width = 0x0,
        .height = 0x0,
        .format = 0x0,
        .usage = 0x10000000000000,
        .need_allocation = 0x0,
        .buffer_count = 0x0,
    },
    [1] = {
        .name = "out0",
        .peer_port_name = "in0",
        .peer_port_node_name = "vo#0",
        .direction = 0x1,
        .width = 0x0,
        .height = 0x0,
        .format = 0x0,
        .usage = 0x10000000000000,
        .need_allocation = 0x0,
        .buffer_count = 0x0,
    },
};

static const struct HdfConfigPipelineSpecsPortSpec g_hdfConfigPortSpec4[] = {
    [0] = {
        .name = "in0",
        .peer_port_name = "out0",
        .peer_port_node_name = "vpss#0",
        .direction = 0x0,
        .width = 0x0,
        .height = 0x0,
        .format = 0x0,
        .usage = 0x10000000000000,
        .need_allocation = 0x0,
        .buffer_count = 0x0,
    },
};

static const struct HdfConfigPipelineSpecsNodeSpec g_hdfConfigNodeSpec[] = {
    [0] = {
        .name = "sensor#0",
        .status = "new",
        .stream_type = "",
        .portSpec = g_hdfConfigPortSpec,
        .portSpecSize = 1,
    },
    [1] = {
        .name = "vi#0",
        .status = "new",
        .stream_type = "",
        .portSpec = g_hdfConfigPortSpec2,
        .portSpecSize = 2,
    },
    [2] = {
        .name = "vpss#0",
        .status = "new",
        .stream_type = "",
        .portSpec = g_hdfConfigPortSpec3,
        .portSpecSize = 2,
    },
    [3] = {
        .name = "vo#0",
        .status = "new",
        .stream_type = "preview",
        .portSpec = g_hdfConfigPortSpec4,
        .portSpecSize = 1,
    },
};

static const struct HdfConfigPipelineSpecsPortSpec g_hdfConfigPortSpec5[] = {
    [0] = {
        .name = "out0",
        .peer_port_name = "in0",
        .peer_port_node_name = "vi#0",
        .direction = 0x1,
        .width = 0x0,
        .height = 0x0,
        .format = 0x0,
        .usage = 0x10000000000000,
        .need_allocation = 0x0,
        .buffer_count = 0x0,
    },
};

static const struct HdfConfigPipelineSpecsPortSpec g_hdfConfigPortSpec6[] = {
    [0] = {
        .name = "in0",
        .peer_port_name = "out0",
        .peer_port_node_name = "sensor#0",
        .direction = 0x0,
        .width = 0x0,
        .height = 0x0,
        .format = 0x0,
        .usage = 0x10000000000000,
        .need_allocation = 0x0,
        .buffer_count = 0x0,
    },
    [1] = {
        .name = "out0",
        .peer_port_name = "in0",
        .peer_port_node_name = "vpss#0",
        .direction = 0x1,
        .width = 0x0,
        .height = 0x0,
        .format = 0x0,
        .usage = 0x10000000000000,
        .need_allocation = 0x0,
        .buffer_count = 0x0,
    },
};

static const struct HdfConfigPipelineSpecsPortSpec g_hdfConfigPortSpec7[] = {
    [0] = {
        .name = "in0",
        .peer_port_name = "out0",
        .peer_port_node_name = "vi#0",
        .direction = 0x0,
        .width = 0x0,
        .height = 0x0,
        .format = 0x0,
        .usage = 0x10000000000000,
        .need_allocation = 0x0,
        .buffer_count = 0x0,
    },
    [1] = {
        .name = "out0",
        .peer_port_name = "in0",
        .peer_port_node_name = "ipp#0",
        .direction = 0x1,
        .width = 0x0,
        .height = 0x0,
        .format = 0x0,
        .usage = 0x10000000000000,
        .need_allocation = 0x0,
        .buffer_count = 0x0,
    },
};

static const struct HdfConfigPipelineSpecsPortSpec g_hdfConfigPortSpec8[] = {
    [0] = {
        .name = "in0",
        .peer_port_name = "out0",
        .peer_port_node_name = "vpss#0",
        .direction = 0x0,
        .width = 0x0,
        .height = 0x0,
        .format = 0x0,
        .usage = 0x10000000000000,
        .need_allocation = 0x0,
        .buffer_count = 0x0,
    },
    [1] = {
        .name = "out0",
        .peer_port_name = "in0",
        .peer_port_node_name = "sink#0",
        .direction = 0x1,
        .width = 0x0,
        .height = 0x0,
        .format = 0x0,
        .usage = 0x10000000000000,
        .need_allocation = 0x0,
        .buffer_count = 0x0,
    },
};

static const struct HdfConfigPipelineSpecsPortSpec g_hdfConfigPortSpec9[] = {
    [0] = {
        .name = "in0",
        .peer_port_name = "out0",
        .peer_port_node_name = "ipp#0",
        .direction = 0x0,
        .width = 0x0,
        .height = 0x0,
        .format = 0x0,
        .usage = 0x10000000000000,
        .need_allocation = 0x0,
        .buffer_count = 0x0,
    },
};

static const struct HdfConfigPipelineSpecsNodeSpec g_hdfConfigNodeSpec2[] = {
    [0] = {
        .name = "sensor#0",
        .status = "new",
        .stream_type = "",
        .portSpec = g_hdfConfigPortSpec5,
        .portSpecSize = 1,
    },
    [1] = {
        .name = "vi#0",
        .status = "new",
        .stream_type = "",
        .portSpec = g_hdfConfigPortSpec6,
        .portSpecSize = 2,
    },
    [2] = {
        .name = "vpss#0",
        .status = "new",
        .stream_type = "",
        .portSpec = g_hdfConfigPortSpec7,
        .portSpecSize = 2,
    },
    [3] = {
        .name = "ipp#0",
        .status = "new",
        .stream_type = "",
        .portSpec = g_hdfConfigPortSpec8,
        .portSpecSize = 2,
    },
    [4] = {
        .name = "sink#0",
        .status = "new",
        .stream_type = "snapshot",
        .portSpec = g_hdfConfigPortSpec9,
        .portSpecSize = 1,
    },
};

static const struct HdfConfigPipelineSpecsPortSpec g_hdfConfigPortSpec10[] = {
    [0] = {
        .name = "out0",
        .peer_port_name = "in0",
        .peer_port_node_name = "vi#0",
        .direction = 0x1,
        .width = 0x0,
        .height = 0x0,
        .format = 0x0,
        .usage = 0x10000000000000,
        .need_allocation = 0x0,
        .buffer_count = 0x0,
    },
};

static const struct HdfConfigPipelineSpecsPortSpec g_hdfConfigPortSpec11[] = {
    [0] = {
        .name = "in0",
        .peer_port_name = "out0",
        .peer_port_node_name = "sensor#0",
        .direction = 0x0,
        .width = 0x0,
        .height = 0x0,
        .format = 0x0,
        .usage = 0x10000000000000,
        .need_allocation = 0x0,
        .buffer_count = 0x0,
    },
    [1] = {
        .name = "out0",
        .peer_port_name = "in0",
        .peer_port_node_name = "vpss#0",
        .direction = 0x1,
        .width = 0x0,
        .height = 0x0,
        .format = 0x0,
        .usage = 0x10000000000000,
        .need_allocation = 0x0,
        .buffer_count = 0x0,
    },
};

static const struct HdfConfigPipelineSpecsPortSpec g_hdfConfigPortSpec12[] = {
    [0] = {
        .name = "in0",
        .peer_port_name = "out0",
        .peer_port_node_name = "vi#0",
        .direction = 0x0,
        .width = 0x0,
        .height = 0x0,
        .format = 0x0,
        .usage = 0x10000000000000,
        .need_allocation = 0x0,
        .buffer_count = 0x0,
    },
    [1] = {
        .name = "out0",
        .peer_port_name = "in0",
        .peer_port_node_name = "vo#0",
        .direction = 0x1,
        .width = 0x0,
        .height = 0x0,
        .format = 0x0,
        .usage = 0x10000000000000,
        .need_allocation = 0x0,
        .buffer_count = 0x0,
    },
    [2] = {
        .name = "out1",
        .peer_port_name = "in0",
        .peer_port_node_name = "ipp#0",
        .direction = 0x1,
        .width = 0x0,
        .height = 0x0,
        .format = 0x0,
        .usage = 0x10000000000000,
        .need_allocation = 0x0,
        .buffer_count = 0x0,
    },
};

static const struct HdfConfigPipelineSpecsPortSpec g_hdfConfigPortSpec13[] = {
    [0] = {
        .name = "in0",
        .peer_port_name = "out1",
        .peer_port_node_name = "vpss#0",
        .direction = 0x0,
        .width = 0x0,
        .height = 0x0,
        .format = 0x0,
        .usage = 0x10000000000000,
        .need_allocation = 0x0,
        .buffer_count = 0x0,
    },
    [1] = {
        .name = "out0",
        .peer_port_name = "in0",
        .peer_port_node_name = "sink#0",
        .direction = 0x1,
        .width = 0x0,
        .height = 0x0,
        .format = 0x0,
        .usage = 0x10000000000000,
        .need_allocation = 0x0,
        .buffer_count = 0x0,
    },
};

static const struct HdfConfigPipelineSpecsPortSpec g_hdfConfigPortSpec14[] = {
    [0] = {
        .name = "in0",
        .peer_port_name = "out0",
        .peer_port_node_name = "vpss#0",
        .direction = 0x0,
        .width = 0x0,
        .height = 0x0,
        .format = 0x0,
        .usage = 0x10000000000000,
        .need_allocation = 0x0,
        .buffer_count = 0x0,
    },
};

static const struct HdfConfigPipelineSpecsPortSpec g_hdfConfigPortSpec15[] = {
    [0] = {
        .name = "in0",
        .peer_port_name = "out0",
        .peer_port_node_name = "ipp#0",
        .direction = 0x0,
        .width = 0x0,
        .height = 0x0,
        .format = 0x0,
        .usage = 0x10000000000000,
        .need_allocation = 0x0,
        .buffer_count = 0x0,
    },
};

static const struct HdfConfigPipelineSpecsNodeSpec g_hdfConfigNodeSpec3[] = {
    [0] = {
        .name = "sensor#0",
        .status = "new",
        .stream_type = "",
        .portSpec = g_hdfConfigPortSpec10,
        .portSpecSize = 1,
    },
    [1] = {
        .name = "vi#0",
        .status = "new",
        .stream_type = "",
        .portSpec = g_hdfConfigPortSpec11,
        .portSpecSize = 2,
    },
    [2] = {
        .name = "vpss#0",
        .status = "new",
        .stream_type = "",
        .portSpec = g_hdfConfigPortSpec12,
        .portSpecSize = 3,
    },
    [3] = {
        .name = "ipp#0",
        .status = "new",
        .stream_type = "",
        .portSpec = g_hdfConfigPortSpec13,
        .portSpecSize = 2,
    },
    [4] = {
        .name = "vo#0",
        .status = "new",
        .stream_type = "preview",
        .portSpec = g_hdfConfigPortSpec14,
        .portSpecSize = 1,
    },
    [5] = {
        .name = "sink#0",
        .status = "new",
        .stream_type = "snapshot",
        .portSpec = g_hdfConfigPortSpec15,
        .portSpecSize = 1,
    },
};

static const struct HdfConfigPipelineSpecsPortSpec g_hdfConfigPortSpec16[] = {
    [0] = {
        .name = "out0",
        .peer_port_name = "in0",
        .peer_port_node_name = "vi#0",
        .direction = 0x1,
        .width = 0x0,
        .height = 0x0,
        .format = 0x0,
        .usage = 0x10000000000000,
        .need_allocation = 0x0,
        .buffer_count = 0x0,
    },
};

static const struct HdfConfigPipelineSpecsPortSpec g_hdfConfigPortSpec17[] = {
    [0] = {
        .name = "in0",
        .peer_port_name = "out0",
        .peer_port_node_name = "sensor#0",
        .direction = 0x0,
        .width = 0x0,
        .height = 0x0,
        .format = 0x0,
        .usage = 0x10000000000000,
        .need_allocation = 0x0,
        .buffer_count = 0x0,
    },
    [1] = {
        .name = "out0",
        .peer_port_name = "in0",
        .peer_port_node_name = "vpss#0",
        .direction = 0x1,
        .width = 0x0,
        .height = 0x0,
        .format = 0x0,
        .usage = 0x10000000000000,
        .need_allocation = 0x0,
        .buffer_count = 0x0,
    },
};

static const struct HdfConfigPipelineSpecsPortSpec g_hdfConfigPortSpec18[] = {
    [0] = {
        .name = "in0",
        .peer_port_name = "out0",
        .peer_port_node_name = "vi#0",
        .direction = 0x0,
        .width = 0x0,
        .height = 0x0,
        .format = 0x0,
        .usage = 0x10000000000000,
        .need_allocation = 0x0,
        .buffer_count = 0x0,
    },
    [1] = {
        .name = "out0",
        .peer_port_name = "in0",
        .peer_port_node_name = "vo#0",
        .direction = 0x1,
        .width = 0x0,
        .height = 0x0,
        .format = 0x0,
        .usage = 0x10000000000000,
        .need_allocation = 0x0,
        .buffer_count = 0x0,
    },
    [2] = {
        .name = "out1",
        .peer_port_name = "in0",
        .peer_port_node_name = "venc#0",
        .direction = 0x1,
        .width = 0x0,
        .height = 0x0,
        .format = 0x0,
        .usage = 0x10000000000000,
        .need_allocation = 0x0,
        .buffer_count = 0x0,
    },
};

static const struct HdfConfigPipelineSpecsPortSpec g_hdfConfigPortSpec19[] = {
    [0] = {
        .name = "in0",
        .peer_port_name = "out0",
        .peer_port_node_name = "vpss#0",
        .direction = 0x0,
        .width = 0x0,
        .height = 0x0,
        .format = 0x0,
        .usage = 0x10000000000000,
        .need_allocation = 0x0,
        .buffer_count = 0x0,
    },
};

static const struct HdfConfigPipelineSpecsPortSpec g_hdfConfigPortSpec20[] = {
    [0] = {
        .name = "in0",
        .peer_port_name = "out1",
        .peer_port_node_name = "vpss#0",
        .direction = 0x0,
        .width = 0x0,
        .height = 0x0,
        .format = 0x0,
        .usage = 0x10000000000000,
        .need_allocation = 0x0,
        .buffer_count = 0x0,
    },
};

static const struct HdfConfigPipelineSpecsNodeSpec g_hdfConfigNodeSpec4[] = {
    [0] = {
        .name = "sensor#0",
        .status = "new",
        .stream_type = "",
        .portSpec = g_hdfConfigPortSpec16,
        .portSpecSize = 1,
    },
    [1] = {
        .name = "vi#0",
        .status = "new",
        .stream_type = "",
        .portSpec = g_hdfConfigPortSpec17,
        .portSpecSize = 2,
    },
    [2] = {
        .name = "vpss#0",
        .status = "new",
        .stream_type = "",
        .portSpec = g_hdfConfigPortSpec18,
        .portSpecSize = 3,
    },
    [3] = {
        .name = "vo#0",
        .status = "new",
        .stream_type = "preview",
        .portSpec = g_hdfConfigPortSpec19,
        .portSpecSize = 1,
    },
    [4] = {
        .name = "venc#0",
        .status = "new",
        .stream_type = "video",
        .portSpec = g_hdfConfigPortSpec20,
        .portSpecSize = 1,
    },
};

static const struct HdfConfigPipelineSpecsPortSpec g_hdfConfigPortSpec21[] = {
    [0] = {
        .name = "out0",
        .peer_port_name = "in0",
        .peer_port_node_name = "vi#0",
        .direction = 0x1,
        .width = 0x0,
        .height = 0x0,
        .format = 0x0,
        .usage = 0x10000000000000,
        .need_allocation = 0x0,
        .buffer_count = 0x0,
    },
};

static const struct HdfConfigPipelineSpecsPortSpec g_hdfConfigPortSpec22[] = {
    [0] = {
        .name = "in0",
        .peer_port_name = "out0",
        .peer_port_node_name = "sensor#0",
        .direction = 0x0,
        .width = 0x0,
        .height = 0x0,
        .format = 0x0,
        .usage = 0x10000000000000,
        .need_allocation = 0x0,
        .buffer_count = 0x0,
    },
    [1] = {
        .name = "out0",
        .peer_port_name = "in0",
        .peer_port_node_name = "vpss#0",
        .direction = 0x1,
        .width = 0x0,
        .height = 0x0,
        .format = 0x0,
        .usage = 0x10000000000000,
        .need_allocation = 0x0,
        .buffer_count = 0x0,
    },
};

static const struct HdfConfigPipelineSpecsPortSpec g_hdfConfigPortSpec23[] = {
    [0] = {
        .name = "in0",
        .peer_port_name = "out0",
        .peer_port_node_name = "vi#0",
        .direction = 0x0,
        .width = 0x0,
        .height = 0x0,
        .format = 0x0,
        .usage = 0x10000000000000,
        .need_allocation = 0x0,
        .buffer_count = 0x0,
    },
    [1] = {
        .name = "out0",
        .peer_port_name = "in0",
        .peer_port_node_name = "vo#0",
        .direction = 0x1,
        .width = 0x0,
        .height = 0x0,
        .format = 0x0,
        .usage = 0x10000000000000,
        .need_allocation = 0x0,
        .buffer_count = 0x0,
    },
    [2] = {
        .name = "out1",
        .peer_port_name = "in0",
        .peer_port_node_name = "vo#1",
        .direction = 0x1,
        .width = 0x0,
        .height = 0x0,
        .format = 0x0,
        .usage = 0x10000000000000,
        .need_allocation = 0x0,
        .buffer_count = 0x0,
    },
};

static const struct HdfConfigPipelineSpecsPortSpec g_hdfConfigPortSpec24[] = {
    [0] = {
        .name = "in0",
        .peer_port_name = "out0",
        .peer_port_node_name = "vpss#0",
        .direction = 0x0,
        .width = 0x0,
        .height = 0x0,
        .format = 0x0,
        .usage = 0x10000000000000,
        .need_allocation = 0x0,
        .buffer_count = 0x0,
    },
};

static const struct HdfConfigPipelineSpecsPortSpec g_hdfConfigPortSpec25[] = {
    [0] = {
        .name = "in0",
        .peer_port_name = "out1",
        .peer_port_node_name = "vpss#0",
        .direction = 0x0,
        .width = 0x0,
        .height = 0x0,
        .format = 0x0,
        .usage = 0x10000000000000,
        .need_allocation = 0x0,
        .buffer_count = 0x0,
    },
};

static const struct HdfConfigPipelineSpecsNodeSpec g_hdfConfigNodeSpec5[] = {
    [0] = {
        .name = "sensor#0",
        .status = "new",
        .stream_type = "",
        .portSpec = g_hdfConfigPortSpec21,
        .portSpecSize = 1,
    },
    [1] = {
        .name = "vi#0",
        .status = "new",
        .stream_type = "",
        .portSpec = g_hdfConfigPortSpec22,
        .portSpecSize = 2,
    },
    [2] = {
        .name = "vpss#0",
        .status = "new",
        .stream_type = "",
        .portSpec = g_hdfConfigPortSpec23,
        .portSpecSize = 3,
    },
    [3] = {
        .name = "vo#0",
        .status = "new",
        .stream_type = "preview",
        .portSpec = g_hdfConfigPortSpec24,
        .portSpecSize = 1,
    },
    [4] = {
        .name = "vo#1",
        .status = "new",
        .stream_type = "preview",
        .portSpec = g_hdfConfigPortSpec25,
        .portSpecSize = 1,
    },
};

static const struct HdfConfigPipelineSpecsRoot g_hdfConfigPipelineSpecsModuleRoot = {
    .module = "pipeline_specs",
    .pipelineSpec = g_hdfConfigPipelineSpec,
    .pipelineSpecSize = 5,
};

const struct HdfConfigPipelineSpecsRoot* HdfGetPipelineSpecsModuleConfigRoot(void)
{
    return &g_hdfConfigPipelineSpecsModuleRoot;
}
