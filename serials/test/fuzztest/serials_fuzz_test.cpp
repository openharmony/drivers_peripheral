/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "serials_fuzz_test.h"

#include <cstddef>
#include <cstdint>
#include <securec.h>
#include <fuzzer/FuzzedDataProvider.h>
#include "hdf_base.h"
#include "serials_common_fuzzer.h"
#include "v1_0/iserials.h"
#include "v1_0/iserial_device_callback.h"

namespace OHOS {
namespace HDI {
namespace Serials {
namespace V1_0 {

class SerialDeviceCallbackFuzz : public ISerialDeviceCallback {
public:
    SerialDeviceCallbackFuzz() = default;
    ~SerialDeviceCallbackFuzz() override = default;

    int32_t OnDeviceOffline() override
    {
        HDF_LOGI("SerialDeviceCallbackFuzz::OnDeviceOffline called");
        return HDF_SUCCESS;
    }

    int32_t OnReadData(const std::vector<int8_t>& data, uint32_t dataLen) override
    {
        (void)data;
        (void)dataLen;
        return HDF_SUCCESS;
    }
};

static sptr<ISerials> g_serialsInterface = nullptr;
static bool g_isInit = false;
static const uint8_t* g_data = nullptr;
static size_t g_dataSize = 0;
static size_t g_pos = 0;

template<class T>
T GetData()
{
    T object {};
    size_t objectSize = sizeof(object);
    if (g_data == nullptr || g_pos >= g_dataSize || objectSize > g_dataSize - g_pos) {
        return object;
    }
    errno_t ret = memcpy_s(&object, objectSize, g_data + g_pos, objectSize);
    if (ret != EOK) {
        return {};
    }
    g_pos += objectSize;
    return object;
}

static SerialConfig GetFuzzConfig(FuzzedDataProvider& provider)
{
    SerialConfig config;
    config.baudRate = GetValidBaudRate(provider.ConsumeIntegral<int32_t>());
    config.dataBits = GetValidDataBits(provider.ConsumeIntegral<int32_t>());
    config.stopBits = GetValidStopBits(provider.ConsumeIntegral<int32_t>());
    config.parity = GetValidParity(provider.ConsumeIntegral<int32_t>());
    config.rtscts = provider.ConsumeBool();
    config.xon = provider.ConsumeBool();
    config.xoff = provider.ConsumeBool();
    config.xany = provider.ConsumeBool();
    return config;
}

static sptr<ISerialDevice> GetFuzzDevice(FuzzedDataProvider& provider, sptr<ISerialDeviceCallback>& callback)
{
    if (g_serialsInterface == nullptr) {
        return nullptr;
    }

    std::vector<SerialDeviceInfo> devices;
    int32_t ret = g_serialsInterface->QueryDevices(devices);
    if (ret != HDF_SUCCESS || devices.empty()) {
        std::string portName = GetFuzzPortName(g_data, g_dataSize);
        SerialConfig config = GetDefaultConfig();
        callback = new SerialDeviceCallbackFuzz();
        sptr<ISerialDevice> device;
        ret = g_serialsInterface->OpenDevice(portName, config, callback, device);
        if (ret != HDF_SUCCESS) {
            return nullptr;
        }
        return device;
    }

    int32_t index = std::abs(provider.ConsumeIntegral<int32_t>()) % static_cast<int32_t>(devices.size());
    SerialConfig config = GetFuzzConfig(provider);
    callback = new SerialDeviceCallbackFuzz();
    sptr<ISerialDevice> device;
    ret = g_serialsInterface->OpenDevice(devices[index].portName, config, callback, device);
    if (ret != HDF_SUCCESS) {
        return nullptr;
    }
    return device;
}

static void FuzzQueryDevices(const uint8_t* data, size_t size)
{
    if (g_serialsInterface == nullptr) {
        return;
    }
    std::vector<SerialDeviceInfo> devices;
    (void)g_serialsInterface->QueryDevices(devices);
}

static void FuzzOpenDevice(const uint8_t* data, size_t size)
{
    if (g_serialsInterface == nullptr) {
        return;
    }
    FuzzedDataProvider provider(data, size);
    sptr<ISerialDeviceCallback> callback;
    sptr<ISerialDevice> device = GetFuzzDevice(provider, callback);
    if (device != nullptr) {
        device->Close();
    }
}

static void FuzzWrite(const uint8_t* data, size_t size)
{
    if (g_serialsInterface == nullptr) {
        return;
    }
    FuzzedDataProvider provider(data, size);
    sptr<ISerialDeviceCallback> callback;
    sptr<ISerialDevice> device = GetFuzzDevice(provider, callback);
    if (device == nullptr) {
        return;
    }

    std::vector<uint8_t> writeData = provider.ConsumeBytes<uint8_t>(
        provider.ConsumeIntegralInRange<uint32_t>(0, FUZZ_MAX_DATA_SIZE));
    int32_t timeout = provider.ConsumeIntegral<int32_t>();
    int32_t bytesWritten = 0;
    (void)device->Write(writeData, timeout, bytesWritten);
    device->Close();
}

static void FuzzStartRead(const uint8_t* data, size_t size)
{
    if (g_serialsInterface == nullptr) {
        return;
    }
    FuzzedDataProvider provider(data, size);
    sptr<ISerialDeviceCallback> callback;
    sptr<ISerialDevice> device = GetFuzzDevice(provider, callback);
    if (device == nullptr) {
        return;
    }

    (void)device->StartRead();
    (void)device->StopRead();
    device->Close();
}

static void FuzzStopRead(const uint8_t* data, size_t size)
{
    if (g_serialsInterface == nullptr) {
        return;
    }
    FuzzedDataProvider provider(data, size);
    sptr<ISerialDeviceCallback> callback;
    sptr<ISerialDevice> device = GetFuzzDevice(provider, callback);
    if (device == nullptr) {
        return;
    }

    (void)device->StopRead();
    device->Close();
}

static void FuzzFlush(const uint8_t* data, size_t size)
{
    if (g_serialsInterface == nullptr) {
        return;
    }
    FuzzedDataProvider provider(data, size);
    sptr<ISerialDeviceCallback> callback;
    sptr<ISerialDevice> device = GetFuzzDevice(provider, callback);
    if (device == nullptr) {
        return;
    }

    (void)device->Flush();
    device->Close();
}

static void FuzzDrain(const uint8_t* data, size_t size)
{
    if (g_serialsInterface == nullptr) {
        return;
    }
    FuzzedDataProvider provider(data, size);
    sptr<ISerialDeviceCallback> callback;
    sptr<ISerialDevice> device = GetFuzzDevice(provider, callback);
    if (device == nullptr) {
        return;
    }

    (void)device->Drain();
    device->Close();
}

static void FuzzSetRtsSignal(const uint8_t* data, size_t size)
{
    if (g_serialsInterface == nullptr) {
        return;
    }
    FuzzedDataProvider provider(data, size);
    sptr<ISerialDeviceCallback> callback;
    sptr<ISerialDevice> device = GetFuzzDevice(provider, callback);
    if (device == nullptr) {
        return;
    }

    bool rts = provider.ConsumeBool();
    (void)device->SetRtsSignal(rts);
    device->Close();
}

static void FuzzGetCtsSignal(const uint8_t* data, size_t size)
{
    if (g_serialsInterface == nullptr) {
        return;
    }
    FuzzedDataProvider provider(data, size);
    sptr<ISerialDeviceCallback> callback;
    sptr<ISerialDevice> device = GetFuzzDevice(provider, callback);
    if (device == nullptr) {
        return;
    }

    bool cts = false;
    (void)device->GetCtsSignal(cts);
    device->Close();
}

static void FuzzSendBrkSignal(const uint8_t* data, size_t size)
{
    if (g_serialsInterface == nullptr) {
        return;
    }
    FuzzedDataProvider provider(data, size);
    sptr<ISerialDeviceCallback> callback;
    sptr<ISerialDevice> device = GetFuzzDevice(provider, callback);
    if (device == nullptr) {
        return;
    }

    (void)device->SendBrkSignal();
    device->Close();
}

static void FuzzClose(const uint8_t* data, size_t size)
{
    if (g_serialsInterface == nullptr) {
        return;
    }
    FuzzedDataProvider provider(data, size);
    sptr<ISerialDeviceCallback> callback;
    sptr<ISerialDevice> device = GetFuzzDevice(provider, callback);
    if (device == nullptr) {
        return;
    }

    (void)device->Close();
}

typedef void (*TestFuncs[])(const uint8_t*, size_t);

TestFuncs g_testFuncs = {
    FuzzQueryDevices,
    FuzzOpenDevice,
    FuzzWrite,
    FuzzStartRead,
    FuzzStopRead,
    FuzzFlush,
    FuzzDrain,
    FuzzSetRtsSignal,
    FuzzGetCtsSignal,
    FuzzSendBrkSignal,
    FuzzClose,
};

bool FuzzTest(const uint8_t* rawData, size_t size)
{
    if (rawData == nullptr) {
        return false;
    }

    if (!g_isInit) {
        g_isInit = true;
        g_serialsInterface = ISerials::Get(true);
        if (g_serialsInterface == nullptr) {
            HDF_LOGE("%{public}s: get ISerials failed", __func__);
            return false;
        }
    }

    g_data = rawData;
    g_dataSize = size;
    g_pos = 0;

    uint32_t code = GetData<uint32_t>();
    uint32_t len = GetArrLength(g_testFuncs);
    if (len == 0) {
        HDF_LOGE("%{public}s: g_testFuncs length is 0", __func__);
        return false;
    }

    g_testFuncs[code % len](rawData, size);
    return true;
}

} // V1_0
} // Serials
} // HDI
} // OHOS

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (size < OHOS::HDI::Serials::V1_0::FUZZ_THRESHOLD) {
        return 0;
    }

    OHOS::HDI::Serials::V1_0::FuzzTest(data, size);
    return 0;
}