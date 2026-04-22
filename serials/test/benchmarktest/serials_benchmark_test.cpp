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

#include <benchmark/benchmark.h>
#include <hdf_log.h>
#include "v1_0/iserials.h"
#include "v1_0/iserial_device_callback.h"

using namespace OHOS::HDI::Serials::V1_0;

namespace {
constexpr int32_t DEFAULT_TIMEOUT = 1000;

class SerialDeviceCallbackBenchmark : public ISerialDeviceCallback {
public:
    SerialDeviceCallbackBenchmark() = default;
    ~SerialDeviceCallbackBenchmark() override = default;

    int32_t OnDeviceOffline() override
    {
        return HDF_SUCCESS;
    }

    int32_t OnReadData(const std::vector<int8_t>& data, uint32_t dataLen) override
    {
        (void)data;
        (void)dataLen;
        return HDF_SUCCESS;
    }
};

SerialConfig GetDefaultConfig()
{
    SerialConfig config;
    config.baudRate = 115200;
    config.dataBits = 8;
    config.stopBits = 1;
    config.parity = 0;
    config.rtscts = false;
    config.xon = false;
    config.xoff = false;
    config.xany = false;
    return config;
}

class SerialsBenchmarkEnvironment : public benchmark::Fixture {
public:
    void SetUp(const benchmark::State& state) override
    {
        serials_ = ISerials::Get(true);
        if (serials_ == nullptr) {
            HDF_LOGE("SerialsBenchmarkEnvironment: get serials service failed");
        }
    }

    void TearDown(const benchmark::State& state) override
    {
        serials_ = nullptr;
    }

    sptr<ISerials> serials_;
};

BENCHMARK_F(SerialsBenchmarkEnvironment, QueryDevices)(benchmark::State& state)
{
    if (serials_ == nullptr) {
        state.SkipWithError("serials service is null");
        return;
    }

    for (auto _ : state) {
        std::vector<SerialDeviceInfo> devices;
        serials_->QueryDevices(devices);
    }
}

BENCHMARK_REGISTER_F(SerialsBenchmarkEnvironment, QueryDevices)->
    Iterations(100)->Repetitions(3)->ReportAggregatesOnly();

BENCHMARK_F(SerialsBenchmarkEnvironment, OpenCloseDevice)(benchmark::State& state)
{
    if (serials_ == nullptr) {
        state.SkipWithError("serials service is null");
        return;
    }
    std::vector<SerialDeviceInfo> devices;
    serials_->QueryDevices(devices);
    if (devices.empty()) {
        return;
    }
    SerialConfig config = GetDefaultConfig();
    sptr<ISerialDeviceCallback> callback = new SerialDeviceCallbackBenchmark();

    for (auto _ : state) {
        sptr<ISerialDevice> device;
        int32_t ret = serials_->OpenDevice(devices.back().portName, config, callback, device);
        if (ret == HDF_SUCCESS && device != nullptr) {
            device->Close();
        }
    }
}

BENCHMARK_REGISTER_F(SerialsBenchmarkEnvironment, OpenCloseDevice)->
    Iterations(100)->Repetitions(3)->ReportAggregatesOnly();

BENCHMARK_DEFINE_F(SerialsBenchmarkEnvironment, WriteData)(benchmark::State& state)
{
    if (serials_ == nullptr) {
        state.SkipWithError("serials service is null");
        return;
    }
    std::vector<SerialDeviceInfo> devices;
    serials_->QueryDevices(devices);
    if (devices.empty()) {
        return;
    }
    SerialConfig config = GetDefaultConfig();
    sptr<ISerialDeviceCallback> callback = new SerialDeviceCallbackBenchmark();
    sptr<ISerialDevice> device;

    int32_t ret = serials_->OpenDevice(devices.back().portName, config, callback, device);
    if (ret != HDF_SUCCESS || device == nullptr) {
        state.SkipWithError("open device failed");
        return;
    }

    std::vector<uint8_t> data(4096, 0xAA);

    for (auto _ : state) {
        int32_t bytesWritten = 0;
        device->Write(data, DEFAULT_TIMEOUT, bytesWritten);
    }

    device->Close();
}

BENCHMARK_REGISTER_F(SerialsBenchmarkEnvironment, WriteData)->
    Iterations(100)->Repetitions(3)->ReportAggregatesOnly();

BENCHMARK_DEFINE_F(SerialsBenchmarkEnvironment, Flush)(benchmark::State& state)
{
    if (serials_ == nullptr) {
        state.SkipWithError("serials service is null");
        return;
    }
    std::vector<SerialDeviceInfo> devices;
    serials_->QueryDevices(devices);
    if (devices.empty()) {
        return;
    }
    SerialConfig config = GetDefaultConfig();
    sptr<ISerialDeviceCallback> callback = new SerialDeviceCallbackBenchmark();
    sptr<ISerialDevice> device;

    int32_t ret = serials_->OpenDevice(devices.back().portName, config, callback, device);
    if (ret != HDF_SUCCESS || device == nullptr) {
        state.SkipWithError("open device failed");
        return;
    }

    for (auto _ : state) {
        device->Flush();
    }

    device->Close();
}

BENCHMARK_REGISTER_F(SerialsBenchmarkEnvironment, Flush)->
    Iterations(100)->Repetitions(3)->ReportAggregatesOnly();

BENCHMARK_DEFINE_F(SerialsBenchmarkEnvironment, Drain)(benchmark::State& state)
{
    if (serials_ == nullptr) {
        state.SkipWithError("serials service is null");
        return;
    }
    std::vector<SerialDeviceInfo> devices;
    serials_->QueryDevices(devices);
    if (devices.empty()) {
        return;
    }
    SerialConfig config = GetDefaultConfig();
    sptr<ISerialDeviceCallback> callback = new SerialDeviceCallbackBenchmark();
    sptr<ISerialDevice> device;

    int32_t ret = serials_->OpenDevice(devices.back().portName, config, callback, device);
    if (ret != HDF_SUCCESS || device == nullptr) {
        state.SkipWithError("open device failed");
        return;
    }

    for (auto _ : state) {
        device->Drain();
    }

    device->Close();
}

BENCHMARK_REGISTER_F(SerialsBenchmarkEnvironment, Drain)->
    Iterations(100)->Repetitions(3)->ReportAggregatesOnly();

BENCHMARK_DEFINE_F(SerialsBenchmarkEnvironment, SetRtsSignal)(benchmark::State& state)
{
    if (serials_ == nullptr) {
        state.SkipWithError("serials service is null");
        return;
    }
    std::vector<SerialDeviceInfo> devices;
    serials_->QueryDevices(devices);
    if (devices.empty()) {
        return;
    }
    SerialConfig config = GetDefaultConfig();
    sptr<ISerialDeviceCallback> callback = new SerialDeviceCallbackBenchmark();
    sptr<ISerialDevice> device;

    int32_t ret = serials_->OpenDevice(devices.back().portName, config, callback, device);
    if (ret != HDF_SUCCESS || device == nullptr) {
        state.SkipWithError("open device failed");
        return;
    }

    bool rts = true;
    for (auto _ : state) {
        device->SetRtsSignal(rts);
        rts = !rts;
    }

    device->Close();
}

BENCHMARK_REGISTER_F(SerialsBenchmarkEnvironment, SetRtsSignal)->
    Iterations(100)->Repetitions(3)->ReportAggregatesOnly();

BENCHMARK_DEFINE_F(SerialsBenchmarkEnvironment, GetCtsSignal)(benchmark::State& state)
{
    if (serials_ == nullptr) {
        state.SkipWithError("serials service is null");
        return;
    }
    std::vector<SerialDeviceInfo> devices;
    serials_->QueryDevices(devices);
    if (devices.empty()) {
        return;
    }
    SerialConfig config = GetDefaultConfig();
    sptr<ISerialDeviceCallback> callback = new SerialDeviceCallbackBenchmark();
    sptr<ISerialDevice> device;

    int32_t ret = serials_->OpenDevice(devices.back().portName, config, callback, device);
    if (ret != HDF_SUCCESS || device == nullptr) {
        state.SkipWithError("open device failed");
        return;
    }

    for (auto _ : state) {
        bool cts = false;
        device->GetCtsSignal(cts);
    }

    device->Close();
}

BENCHMARK_REGISTER_F(SerialsBenchmarkEnvironment, GetCtsSignal)->
    Iterations(100)->Repetitions(3)->ReportAggregatesOnly();

BENCHMARK_DEFINE_F(SerialsBenchmarkEnvironment, StartStopRead)(benchmark::State& state)
{
    if (serials_ == nullptr) {
        state.SkipWithError("serials service is null");
        return;
    }
    std::vector<SerialDeviceInfo> devices;
    serials_->QueryDevices(devices);
    if (devices.empty()) {
        return;
    }
    SerialConfig config = GetDefaultConfig();
    sptr<ISerialDeviceCallback> callback = new SerialDeviceCallbackBenchmark();
    sptr<ISerialDevice> device;

    int32_t ret = serials_->OpenDevice(devices.back().portName, config, callback, device);
    if (ret != HDF_SUCCESS || device == nullptr) {
        state.SkipWithError("open device failed");
        return;
    }

    for (auto _ : state) {
        device->StartRead();
        device->StopRead();
    }

    device->Close();
}

BENCHMARK_REGISTER_F(SerialsBenchmarkEnvironment, StartStopRead)->
    Iterations(100)->Repetitions(3)->ReportAggregatesOnly();

BENCHMARK_DEFINE_F(SerialsBenchmarkEnvironment, SendBrkSignal)(benchmark::State& state)
{
    if (serials_ == nullptr) {
        state.SkipWithError("serials service is null");
        return;
    }
    std::vector<SerialDeviceInfo> devices;
    serials_->QueryDevices(devices);
    if (devices.empty()) {
        return;
    }
    SerialConfig config = GetDefaultConfig();
    sptr<ISerialDeviceCallback> callback = new SerialDeviceCallbackBenchmark();
    sptr<ISerialDevice> device;

    int32_t ret = serials_->OpenDevice(devices.back().portName, config, callback, device);
    if (ret != HDF_SUCCESS || device == nullptr) {
        state.SkipWithError("open device failed");
        return;
    }

    for (auto _ : state) {
        device->SendBrkSignal();
    }

    device->Close();
}

BENCHMARK_REGISTER_F(SerialsBenchmarkEnvironment, SendBrkSignal)->
    Iterations(100)->Repetitions(3)->ReportAggregatesOnly();
}
BENCHMARK_MAIN();