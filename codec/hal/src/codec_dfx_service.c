/*
 * Copyright (c) 2023 Shenzhen Kaihong DID Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include "codec_dfx_service.h"
#include <hdf_base.h>
#include <hdf_log.h>
#include "codec_adapter_interface.h"
#include "codec_component_manager_service.h"

#define HDF_LOG_TAG codec_dfx_server
#define CODEC_MAX_DFX_DUMP_LEN  256

int32_t DevCodecHostDump(struct HdfSBuf *data, struct HdfSBuf *reply)
{
    uint32_t argv = 0;
    (void)HdfSbufReadUint32(data, &argv);
    if (argv != 1) {
        HdfSbufWriteString(reply, "please enter -h for help!! \n");
        return HDF_SUCCESS;
    }
    const char *para = HdfSbufReadString(data);
    if (strcmp(para, "-h") == 0) {
        HdfSbufWriteString(reply, "-h: codec dump help ! \n");
        HdfSbufWriteString(reply, "-l: dump codec components info list ! \n");
        return HDF_SUCCESS;
    }

    if (strcmp(para, "-l") == 0) {
        struct CodecComponentManagerSerivce *managerService = CodecComponentManagerSerivceGet();
        struct ComponentTypeNode *pos = NULL;
        struct ComponentTypeNode *next = NULL;
        
        DLIST_FOR_EACH_ENTRY_SAFE(pos, next, &managerService->head, struct ComponentTypeNode, node)
        {
            if (pos == NULL) {
                HDF_LOGE("%{public}s: pos is NULL", __func__);
                return HDF_FAILURE;
            }
            struct CodecComponentNode *codecNode = CodecComponentTypeServiceGetCodecNode(pos->service);
            if (codecNode != NULL) {
                char dump[CODEC_MAX_DFX_DUMP_LEN + 1] = { 0 };
                int32_t ret = OmxAdapterWriteDumperData(dump, CODEC_MAX_DFX_DUMP_LEN, pos->componentId, codecNode);
                if (ret != HDF_SUCCESS) {
                    HDF_LOGE("%{public}s: OmxAdapterWriteDumperData err", __func__);
                    return HDF_FAILURE;
                }
                HdfSbufWriteString(reply, dump);
                HdfSbufWriteString(reply, "------------------------------------------------------------------------");
            }
        }
        HDF_LOGI("%{public}s: codec hidumper success!", __func__);
        return HDF_SUCCESS;
    }
    HdfSbufWriteString(reply, "unknow param, please enter -h for help! \n");
    return HDF_SUCCESS;
}
