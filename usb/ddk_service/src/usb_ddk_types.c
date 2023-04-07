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

#include "usb_ddk_inner_types.h"
#include <hdf_log.h>
#include <hdf_sbuf.h>
#include <osal_mem.h>
#include <securec.h>

bool WritePodArray(struct HdfSBuf *parcel, const void *data, uint32_t elementSize, uint32_t count)
{
    if (!HdfSbufWriteUint32(parcel, count)) {
        HDF_LOGE("%{public}s: failed to write array size", __func__);
        return false;
    }

    if (data == NULL && count == 0) {
        return true;
    }

    if (!HdfSbufWriteUnpadBuffer(parcel, (const uint8_t *)data, elementSize * count)) {
        HDF_LOGE("%{public}s: failed to write array", __func__);
        return false;
    }

    return true;
}

bool UsbControlRequestSetupBlockMarshalling(struct HdfSBuf *data, const struct UsbControlRequestSetup *dataBlock)
{
    if (data == NULL) {
        HDF_LOGE("%{public}s: invalid sbuf", __func__);
        return false;
    }

    if (dataBlock == NULL) {
        HDF_LOGE("%{public}s: invalid data block", __func__);
        return false;
    }

    if (!HdfSbufWriteUnpadBuffer(data, (const uint8_t *)dataBlock, sizeof(struct UsbControlRequestSetup))) {
        HDF_LOGE("%{public}s: failed to write buffer data", __func__);
        return false;
    }
    return true;
}

bool UsbControlRequestSetupBlockUnmarshalling(struct HdfSBuf *data, struct UsbControlRequestSetup *dataBlock)
{
    if (data == NULL) {
        HDF_LOGE("%{public}s: invalid sbuf", __func__);
        return false;
    }

    if (dataBlock == NULL) {
        HDF_LOGE("%{public}s: invalid data block", __func__);
        return false;
    }

    const struct UsbControlRequestSetup *dataBlockPtr =
        (const struct UsbControlRequestSetup *)HdfSbufReadUnpadBuffer(data, sizeof(struct UsbControlRequestSetup));
    if (dataBlockPtr == NULL) {
        HDF_LOGE("%{public}s: failed to read buffer data", __func__);
        goto ERRORS;
    }

    if (memcpy_s(dataBlock, sizeof(struct UsbControlRequestSetup), dataBlockPtr,
            sizeof(struct UsbControlRequestSetup)) != EOK) {
        HDF_LOGE("%{public}s: failed to memcpy data", __func__);
        goto ERRORS;
    }

    return true;
ERRORS:
    return false;
}

void UsbControlRequestSetupFree(struct UsbControlRequestSetup *dataBlock, bool freeSelf)
{
    if (dataBlock == NULL) {
        return;
    }

    if (freeSelf) {
        OsalMemFree(dataBlock);
    }
}

bool UsbDeviceDescriptorBlockMarshalling(struct HdfSBuf *data, const struct UsbDeviceDescriptor *dataBlock)
{
    if (data == NULL) {
        HDF_LOGE("%{public}s: invalid sbuf", __func__);
        return false;
    }

    if (dataBlock == NULL) {
        HDF_LOGE("%{public}s: invalid data block", __func__);
        return false;
    }

    if (!HdfSbufWriteUnpadBuffer(data, (const uint8_t *)dataBlock, sizeof(struct UsbDeviceDescriptor))) {
        HDF_LOGE("%{public}s: failed to write buffer data", __func__);
        return false;
    }
    return true;
}

bool UsbDeviceDescriptorBlockUnmarshalling(struct HdfSBuf *data, struct UsbDeviceDescriptor *dataBlock)
{
    if (data == NULL) {
        HDF_LOGE("%{public}s: invalid sbuf", __func__);
        return false;
    }

    if (dataBlock == NULL) {
        HDF_LOGE("%{public}s: invalid data block", __func__);
        return false;
    }

    const struct UsbDeviceDescriptor *dataBlockPtr =
        (const struct UsbDeviceDescriptor *)HdfSbufReadUnpadBuffer(data, sizeof(struct UsbDeviceDescriptor));
    if (dataBlockPtr == NULL) {
        HDF_LOGE("%{public}s: failed to read buffer data", __func__);
        goto ERRORS;
    }

    if (memcpy_s(dataBlock, sizeof(struct UsbDeviceDescriptor), dataBlockPtr, sizeof(struct UsbDeviceDescriptor)) !=
        EOK) {
        HDF_LOGE("%{public}s: failed to memcpy data", __func__);
        goto ERRORS;
    }

    return true;
ERRORS:
    return false;
}

void UsbDeviceDescriptorFree(struct UsbDeviceDescriptor *dataBlock, bool freeSelf)
{
    if (dataBlock == NULL) {
        return;
    }

    if (freeSelf) {
        OsalMemFree(dataBlock);
    }
}

bool UsbRequestPipeBlockMarshalling(struct HdfSBuf *data, const struct UsbRequestPipe *dataBlock)
{
    if (data == NULL) {
        HDF_LOGE("%{public}s: invalid sbuf", __func__);
        return false;
    }

    if (dataBlock == NULL) {
        HDF_LOGE("%{public}s: invalid data block", __func__);
        return false;
    }

    if (!HdfSbufWriteUnpadBuffer(data, (const uint8_t *)dataBlock, sizeof(struct UsbRequestPipe))) {
        HDF_LOGE("%{public}s: failed to write buffer data", __func__);
        return false;
    }
    return true;
}

bool UsbRequestPipeBlockUnmarshalling(struct HdfSBuf *data, struct UsbRequestPipe *dataBlock)
{
    if (data == NULL) {
        HDF_LOGE("%{public}s: invalid sbuf", __func__);
        return false;
    }

    if (dataBlock == NULL) {
        HDF_LOGE("%{public}s: invalid data block", __func__);
        return false;
    }

    const struct UsbRequestPipe *dataBlockPtr =
        (const struct UsbRequestPipe *)HdfSbufReadUnpadBuffer(data, sizeof(struct UsbRequestPipe));
    if (dataBlockPtr == NULL) {
        HDF_LOGE("%{public}s: failed to read buffer data", __func__);
        goto ERRORS;
    }

    if (memcpy_s(dataBlock, sizeof(struct UsbRequestPipe), dataBlockPtr, sizeof(struct UsbRequestPipe)) != EOK) {
        HDF_LOGE("%{public}s: failed to memcpy data", __func__);
        goto ERRORS;
    }

    return true;
ERRORS:
    return false;
}

void UsbRequestPipeFree(struct UsbRequestPipe *dataBlock, bool freeSelf)
{
    if (dataBlock == NULL) {
        return;
    }

    if (freeSelf) {
        OsalMemFree(dataBlock);
    }
}
