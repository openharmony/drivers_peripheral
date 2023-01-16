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

#ifndef MOCK_LINUX_ADAPTER_H
#define MOCK_LINUX_ADAPTER_H

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "linux_adapter.h"

int32_t FuncAdapterInit(const UsbSession *session);
void FuncAdapterExit(const UsbSession *session);
UsbDeviceHandle *FuncAdapterOpenDevice(UsbSession *session, uint8_t busNum, uint8_t usbAddr);
void FuncAdapterCloseDevice(UsbDeviceHandle *handle);
int32_t FuncAdapterGetConfigDescriptor(const UsbDevice *dev, uint8_t configIndex, void *buffer, size_t len);
int32_t FuncAdapterGetConfiguration(const UsbDeviceHandle *handle, uint8_t *activeConfig);
int32_t FuncAdapterSetConfiguration(UsbDeviceHandle *handle, int32_t activeConfig);
int32_t FuncAdapterClaimInterface(const UsbDeviceHandle *handle, uint32_t interfaceNumber);
int32_t FuncAdapterReleaseInterface(const UsbDeviceHandle *handle, uint32_t interfaceNumber);
int32_t FuncAdapterSetInterface(const UsbDeviceHandle *handle, uint8_t interface, uint8_t altSetting);
int32_t FuncAdapterClearHalt(const UsbDeviceHandle *handle, uint32_t endPoint);
int32_t FuncAdapterResetDevice(const UsbDeviceHandle *handle);
UsbHostRequest *FuncAdapterAllocRequest(const UsbDeviceHandle *handle, int32_t isoPackets, size_t len);
int32_t FuncAdapterFreeRequest(UsbHostRequest *request);
int32_t FuncAdapterSubmitRequest(UsbHostRequest *request);
int32_t FuncAdapterCancelRequest(UsbHostRequest * const request);
int32_t FuncAdapterUrbCompleteHandle(const UsbDeviceHandle *devHandle);

#endif
