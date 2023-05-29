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

#include <cstdio>
#include <cstdlib>
#include <unistd.h>
#include "hdf_base.h"

#ifdef __cplusplus
extern "C" {
    int32_t AudioEffectGetConfigDescriptor(const char *path, struct ConfigDescriptor **cfgDesc);
    void AudioEffectReleaseCfgDesc(struct ConfigDescriptor *cfgDesc);
}
#endif

static bool DoSomethingInterestingWithMyAPI(const uint8_t *rawData, size_t size)
{
    if (rawData == NULL) {
        return false;
    }

    // Create a temporary file with the data
    char tmpfile[] = "/tmp/fuzz-XXXXXX";
    int fd = mkstemp(tmpfile);
    if (fd < 0) {
        return 0;
    }
    write(fd, rawData, size);
    close(fd);

    struct ConfigDescriptor *cfgDesc;
    // Call the interface with the temporary file
    int ret = AudioEffectGetConfigDescriptor(tmpfile, &cfgDesc);
    if (ret != HDF_SUCCESS) {
        return false;
    }
    AudioEffectReleaseCfgDesc(cfgDesc);

    // Remove the temporary file
    remove(tmpfile);
    return true;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    DoSomethingInterestingWithMyAPI(data, size);

    return 0;
}
