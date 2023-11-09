/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "wifi_hal_p2p_feature.h"
#include "hdf_base.h"
#include "hdf_log.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

int32_t InitP2pFeature(struct IWiFiP2p **fe)
{
    if (fe == NULL || *fe == NULL) {
        HDF_LOGE("%s: input parameter invalid, line: %d", __FUNCTION__, __LINE__);
        return HDF_ERR_INVALID_PARAM;
    }
    if (InitBaseFeature((struct IWiFiBaseFeature **)fe) != HDF_SUCCESS) {
        HDF_LOGE("%s: init base feature, line: %d", __FUNCTION__, __LINE__);
        return HDF_FAILURE;
    }
    return HDF_SUCCESS;
}

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif