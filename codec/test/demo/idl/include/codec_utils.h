/*
 * Copyright 2023 Shenzhen Kaihong DID Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * 		http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef CODEC_UTIL_H
#define CODEC_UTIL_H

#include <list>
#include <map>
#include <securec.h>
#include "hdf_log.h"
#include <OMX_Component.h>
class CodecUtil {
public:
    template <typename T>
    int32_t InitParam(T &param)
    {
        auto ret = memset_s(&param, sizeof(param), 0x0, sizeof(param));
        if (ret != EOK) {
            HDF_LOGE("%{public}s error, memset_s ret [%{public}d", __func__, ret);
            return HDF_FAILURE;
        }
        param.nSize = sizeof(param);
        param.nVersion.s.nVersionMajor = 1;  // mVersion.s.nVersionMajor;
        return HDF_SUCCESS;
    }

    template <typename T>
    int32_t InitParamInOhos(T &param)
    {
        auto ret = memset_s(&param, sizeof(param), 0x0, sizeof(param));
        if (ret != EOK) {
            HDF_LOGE("%{public}s error, memset_s ret [%{public}d", __func__, ret);
            return HDF_FAILURE;
        }
        param.size = sizeof(param);
        param.version.s.nVersionMajor = 1;  // mVersion.s.nVersionMajor;
        return HDF_SUCCESS;
    }

    template <typename T>
    void ObjectToVector(T &param, std::vector<int8_t> &vec)
    {
        vec.clear();
        int8_t *paramPointer = (int8_t *)&param;
        vec.insert(vec.end(), paramPointer, paramPointer + sizeof(param));
    }

    template <typename T>
    int32_t VectorToObject(std::vector<int8_t> &vec, T &param)
    {
        auto ret = memcpy_s(&param, sizeof(param), vec.data(), vec.size());
        if (ret != EOK) {
            HDF_LOGE("%{public}s error, memset_s ret [%{public}d", __func__, ret);
            return HDF_FAILURE;
        }
        vec.clear();
        return HDF_SUCCESS;
    }

    void setParmValue(OMX_PARAM_PORTDEFINITIONTYPE &param, uint32_t width, uint32_t height, uint32_t stride)
    {
        param.format.video.nFrameWidth = width;
        param.format.video.nFrameHeight = height;
        param.format.video.nStride = stride;
        param.format.video.nSliceHeight = height;
    }
};
#endif /* CODEC_UTIL_H */
