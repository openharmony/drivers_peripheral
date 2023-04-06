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

#include "usb_ddk_types.h"
#ifndef HDI_BUFF_MAX_SIZE
#define HDI_BUFF_MAX_SIZE (1024 * 200)
#endif

struct HdfSBuf;
bool WritePodArray(struct HdfSBuf *parcel, const void *data, uint32_t elementSize, uint32_t count);

bool UsbControlRequestSetupBlockMarshalling(struct HdfSBuf *data, const struct UsbControlRequestSetup *dataBlock);

bool UsbControlRequestSetupBlockUnmarshalling(struct HdfSBuf *data, struct UsbControlRequestSetup *dataBlock);

void UsbControlRequestSetupFree(struct UsbControlRequestSetup *dataBlock, bool freeSelf);

bool UsbDeviceDescriptorBlockMarshalling(struct HdfSBuf *data, const struct UsbDeviceDescriptor *dataBlock);

bool UsbDeviceDescriptorBlockUnmarshalling(struct HdfSBuf *data, struct UsbDeviceDescriptor *dataBlock);

void UsbDeviceDescriptorFree(struct UsbDeviceDescriptor *dataBlock, bool freeSelf);

bool UsbRequestPipeBlockMarshalling(struct HdfSBuf *data, const struct UsbRequestPipe *dataBlock);

bool UsbRequestPipeBlockUnmarshalling(struct HdfSBuf *data, struct UsbRequestPipe *dataBlock);

void UsbRequestPipeFree(struct UsbRequestPipe *dataBlock, bool freeSelf);