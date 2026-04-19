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

#include <gtest/gtest.h>
#include <hdf_log.h>
#include <condition_variable>
#include <mutex>
#include "v1_0/iserials.h"
#include "v1_0/iserial_device_callback.h"

using namespace OHOS::HDI::Serials::V1_0;
using namespace testing::ext;

constexpr int32_t TEST_WAIT_DATA_TIMEOUT_MS = 1000;
constexpr int32_t TEST_WAIT_OFFLINE_TIMEOUT_MS = 5000;
constexpr int32_t TEST_WRITE_TIMEOUT_MS = 1000;
constexpr int32_t TEST_LARGE_DATA_SIZE = 5000;
constexpr int32_t TEST_MIN_DEVICES_COUNT = 2;
constexpr int32_t DEFAULT_BAUD_RATE = 115200;
constexpr int32_t TEST_BAUD_RATE_9600 = 9600;
constexpr int32_t DATA_BIT_8 = 8;
class SerialDeviceCallbackImpl : public ISerialDeviceCallback {
public:
    SerialDeviceCallbackImpl() : deviceOffline_(false), dataReceived_(false) {}
    ~SerialDeviceCallbackImpl() override = default;

    int32_t OnDeviceOffline() override
    {
        deviceOffline_ = true;
        offlineCond_.notify_all();
        HDF_LOGI("Device offline notified");
        return HDF_SUCCESS;
    }

    int32_t OnReadData(const std::vector<int8_t>& data, uint32_t dataLen) override
    {
        std::lock_guard<std::mutex> lock(dataMutex_);
        receivedData_ = data;
        receivedLen_ = dataLen;
        dataReceived_ = true;
        dataCond_.notify_one();
        return HDF_SUCCESS;
    }

    bool WaitForData(std::vector<int8_t>& data, uint32_t& dataLen, int timeoutMs = TEST_WAIT_DATA_TIMEOUT_MS)
    {
        std::unique_lock<std::mutex> lock(dataMutex_);
        return dataCond_.wait_for(lock, std::chrono::milliseconds(timeoutMs),
            [this] { return dataReceived_.load(); }) && dataReceived_.load();
    }

    bool WaitForOffline(int timeoutMs = TEST_WAIT_OFFLINE_TIMEOUT_MS)
    {
        std::unique_lock<std::mutex> lock(offlineMutex_);
        return offlineCond_.wait_for(lock, std::chrono::milliseconds(timeoutMs),
            [this] { return deviceOffline_.load(); }) && deviceOffline_.load();
    }

    bool IsDeviceOffline() const { return deviceOffline_; }
    void Reset() { deviceOffline_ = false; dataReceived_ = false; }

private:
    std::atomic<bool> deviceOffline_;
    std::atomic<bool> dataReceived_;
    std::mutex dataMutex_;
    std::mutex offlineMutex_;
    std::condition_variable dataCond_;
    std::condition_variable offlineCond_;
    std::vector<int8_t> receivedData_;
    uint32_t receivedLen_ = 0;
};

class HdfSerialsTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();

    static sptr<ISerials> serials_;
    static SerialConfig defaultConfig_;
};

sptr<ISerials> HdfSerialsTest::serials_ = nullptr;
SerialConfig HdfSerialsTest::defaultConfig_ = {};

void HdfSerialsTest::SetUpTestCase()
{
    HDF_LOGI("HdfSerialsTest::SetUpTestCase");
    serials_ = ISerials::Get(true);
    ASSERT_NE(serials_, nullptr);

    defaultConfig_.baudRate = DEFAULT_BAUD_RATE;
    defaultConfig_.dataBits = 8;
    defaultConfig_.stopBits = 0;
    defaultConfig_.parity = 0;
    defaultConfig_.rtscts = false;
    defaultConfig_.xon = false;
    defaultConfig_.xoff = false;
    defaultConfig_.xany = false;
}

void HdfSerialsTest::TearDownTestCase()
{
    HDF_LOGI("HdfSerialsTest::TearDownTestCase");
    serials_ = nullptr;
}

void HdfSerialsTest::SetUp()
{
    HDF_LOGI("HdfSerialsTest::SetUp");
}

void HdfSerialsTest::TearDown()
{
    HDF_LOGI("HdfSerialsTest::TearDown");
}

HWTEST_F(HdfSerialsTest, QueryDevices_001, TestSize.Level0)
{
    ASSERT_NE(serials_, nullptr);

    std::vector<SerialDeviceInfo> devices;
    int32_t ret = serials_->QueryDevices(devices);
    EXPECT_EQ(ret, HDF_SUCCESS);
    EXPECT_GE(devices.size(), 0);
}

HWTEST_F(HdfSerialsTest, QueryDevices_002, TestSize.Level1)
{
    ASSERT_NE(serials_, nullptr);

    std::vector<SerialDeviceInfo> devices;
    int32_t ret = serials_->QueryDevices(devices);
    EXPECT_EQ(ret, HDF_SUCCESS);

    for (const auto& device : devices) {
        EXPECT_FALSE(device.portName.empty());
        HDF_LOGI("Device: portName=%{public}s, manufacturer=%{public}s",
            device.portName.c_str(), device.manufacturer.c_str());
    }
}

HWTEST_F(HdfSerialsTest, OpenDevice_001, TestSize.Level0)
{
    ASSERT_NE(serials_, nullptr);
    std::vector<SerialDeviceInfo> devices;
    int32_t ret = serials_->QueryDevices(devices);
    EXPECT_EQ(ret, HDF_SUCCESS);
    if (devices.empty()) {
        return;
    }

    sptr<SerialDeviceCallbackImpl> callback = new SerialDeviceCallbackImpl();
    sptr<ISerialDevice> device;
    ret = serials_->OpenDevice(devices[0].portName, defaultConfig_, callback, device);
    EXPECT_EQ(ret, HDF_SUCCESS);
    EXPECT_NE(device, nullptr);

    if (device != nullptr) {
        device->Close();
    }
}

HWTEST_F(HdfSerialsTest, OpenDevice_002, TestSize.Level1)
{
    ASSERT_NE(serials_, nullptr);
    std::vector<SerialDeviceInfo> devices;
    int32_t ret = serials_->QueryDevices(devices);
    EXPECT_EQ(ret, HDF_SUCCESS);
    if (devices.empty()) {
        return;
    }

    SerialConfig config;
    config.baudRate = TEST_BAUD_RATE_9600;
    config.dataBits = DATA_BIT_8;
    config.stopBits = 0;
    config.parity = 0;
    config.rtscts = false;
    config.xon = false;
    config.xoff = false;
    config.xany = false;

    sptr<SerialDeviceCallbackImpl> callback = new SerialDeviceCallbackImpl();
    sptr<ISerialDevice> device;
    ret = serials_->OpenDevice(devices[0].portName, config, callback, device);
    EXPECT_EQ(ret, HDF_SUCCESS);
    EXPECT_NE(device, nullptr);

    if (device != nullptr) {
        device->Close();
    }
}

HWTEST_F(HdfSerialsTest, OpenDevice_003, TestSize.Level1)
{
    ASSERT_NE(serials_, nullptr);
    std::vector<SerialDeviceInfo> devices;
    int32_t ret = serials_->QueryDevices(devices);
    EXPECT_EQ(ret, HDF_SUCCESS);
    if (devices.empty()) {
        return;
    }

    sptr<SerialDeviceCallbackImpl> callback = new SerialDeviceCallbackImpl();
    sptr<ISerialDevice> device1;
    ret = serials_->OpenDevice(devices[0].portName, defaultConfig_, callback, device1);
    EXPECT_EQ(ret, HDF_SUCCESS);

    sptr<ISerialDevice> device2;
    ret = serials_->OpenDevice(devices[0].portName, defaultConfig_, callback, device2);
    EXPECT_EQ(ret, HDF_ERR_DEVICE_BUSY);

    if (device1 != nullptr) {
        device1->Close();
    }
}

HWTEST_F(HdfSerialsTest, OpenDevice_004, TestSize.Level1)
{
    ASSERT_NE(serials_, nullptr);

    sptr<SerialDeviceCallbackImpl> callback = new SerialDeviceCallbackImpl();
    sptr<ISerialDevice> device;
    int32_t ret = serials_->OpenDevice("/dev/nonexistent", defaultConfig_, callback, device);
    EXPECT_NE(ret, HDF_SUCCESS);
}

HWTEST_F(HdfSerialsTest, OpenDevice_005, TestSize.Level1)
{
    ASSERT_NE(serials_, nullptr);
    std::vector<SerialDeviceInfo> devices;
    int32_t ret = serials_->QueryDevices(devices);
    EXPECT_EQ(ret, HDF_SUCCESS);
    if (devices.empty()) {
        return;
    }

    sptr<ISerialDevice> device;
    ret = serials_->OpenDevice(devices[0].portName, defaultConfig_, nullptr, device);
    EXPECT_EQ(ret, HDF_SUCCESS);
    EXPECT_NE(device, nullptr);

    if (device != nullptr) {
        device->Close();
    }
}

HWTEST_F(HdfSerialsTest, Write_001, TestSize.Level0)
{
    ASSERT_NE(serials_, nullptr);
    std::vector<SerialDeviceInfo> devices;
    int32_t ret = serials_->QueryDevices(devices);
    EXPECT_EQ(ret, HDF_SUCCESS);
    if (devices.empty()) {
        return;
    }

    sptr<SerialDeviceCallbackImpl> callback = new SerialDeviceCallbackImpl();
    sptr<ISerialDevice> device;
    ret = serials_->OpenDevice(devices[0].portName, defaultConfig_, callback, device);
    ASSERT_EQ(ret, HDF_SUCCESS);
    ASSERT_NE(device, nullptr);

    std::vector<uint8_t> data = {0x01, 0x02, 0x03, 0x04};
    int32_t bytesWritten = 0;
    ret = device->Write(data, TEST_WRITE_TIMEOUT_MS, bytesWritten);
    EXPECT_EQ(ret, HDF_SUCCESS);
    EXPECT_EQ(bytesWritten, static_cast<int32_t>(data.size()));

    device->Close();
}

HWTEST_F(HdfSerialsTest, Write_002, TestSize.Level1)
{
    ASSERT_NE(serials_, nullptr);
    std::vector<SerialDeviceInfo> devices;
    int32_t ret = serials_->QueryDevices(devices);
    EXPECT_EQ(ret, HDF_SUCCESS);
    if (devices.empty()) {
        return;
    }

    sptr<SerialDeviceCallbackImpl> callback = new SerialDeviceCallbackImpl();
    sptr<ISerialDevice> device;
    ret = serials_->OpenDevice(devices[0].portName, defaultConfig_, callback, device);
    ASSERT_EQ(ret, HDF_SUCCESS);
    ASSERT_NE(device, nullptr);

    std::vector<uint8_t> emptyData;
    int32_t bytesWritten = 0;
    ret = device->Write(emptyData, TEST_WRITE_TIMEOUT_MS, bytesWritten);
    EXPECT_NE(ret, HDF_SUCCESS);

    device->Close();
}

HWTEST_F(HdfSerialsTest, Write_003, TestSize.Level1)
{
    ASSERT_NE(serials_, nullptr);
    std::vector<SerialDeviceInfo> devices;
    int32_t ret = serials_->QueryDevices(devices);
    EXPECT_EQ(ret, HDF_SUCCESS);
    if (devices.empty()) {
        return;
    }

    sptr<SerialDeviceCallbackImpl> callback = new SerialDeviceCallbackImpl();
    sptr<ISerialDevice> device;
    ret = serials_->OpenDevice(devices[0].portName, defaultConfig_, callback, device);
    ASSERT_EQ(ret, HDF_SUCCESS);
    ASSERT_NE(device, nullptr);

    std::vector<uint8_t> largeData(TEST_LARGE_DATA_SIZE, 0x55);
    int32_t bytesWritten = 0;
    ret = device->Write(largeData, TEST_WRITE_TIMEOUT_MS, bytesWritten);
    EXPECT_NE(ret, HDF_SUCCESS);

    device->Close();
}

HWTEST_F(HdfSerialsTest, StartRead_001, TestSize.Level0)
{
    ASSERT_NE(serials_, nullptr);
    std::vector<SerialDeviceInfo> devices;
    int32_t ret = serials_->QueryDevices(devices);
    EXPECT_EQ(ret, HDF_SUCCESS);
    if (devices.empty()) {
        return;
    }

    sptr<SerialDeviceCallbackImpl> callback = new SerialDeviceCallbackImpl();
    sptr<ISerialDevice> device;
    ret = serials_->OpenDevice(devices[0].portName, defaultConfig_, callback, device);
    ASSERT_EQ(ret, HDF_SUCCESS);
    ASSERT_NE(device, nullptr);

    ret = device->StartRead();
    EXPECT_EQ(ret, HDF_SUCCESS);

    ret = device->StopRead();
    EXPECT_EQ(ret, HDF_SUCCESS);

    device->Close();
}

HWTEST_F(HdfSerialsTest, StartRead_002, TestSize.Level1)
{
    ASSERT_NE(serials_, nullptr);
    std::vector<SerialDeviceInfo> devices;
    int32_t ret = serials_->QueryDevices(devices);
    EXPECT_EQ(ret, HDF_SUCCESS);
    if (devices.empty()) {
        return;
    }

    sptr<SerialDeviceCallbackImpl> callback = new SerialDeviceCallbackImpl();
    sptr<ISerialDevice> device;
    ret = serials_->OpenDevice(devices[0].portName, defaultConfig_, callback, device);
    ASSERT_EQ(ret, HDF_SUCCESS);
    ASSERT_NE(device, nullptr);

    ret = device->StartRead();
    EXPECT_EQ(ret, HDF_SUCCESS);

    ret = device->StartRead();
    EXPECT_EQ(ret, HDF_SUCCESS);

    ret = device->StopRead();
    EXPECT_EQ(ret, HDF_SUCCESS);

    device->Close();
}

HWTEST_F(HdfSerialsTest, Close_001, TestSize.Level0)
{
    ASSERT_NE(serials_, nullptr);
    std::vector<SerialDeviceInfo> devices;
    int32_t ret = serials_->QueryDevices(devices);
    EXPECT_EQ(ret, HDF_SUCCESS);
    if (devices.empty()) {
        return;
    }

    sptr<SerialDeviceCallbackImpl> callback = new SerialDeviceCallbackImpl();
    sptr<ISerialDevice> device;
    ret = serials_->OpenDevice(devices[0].portName, defaultConfig_, callback, device);
    ASSERT_EQ(ret, HDF_SUCCESS);
    ASSERT_NE(device, nullptr);

    ret = device->Close();
    EXPECT_EQ(ret, HDF_SUCCESS);
}

HWTEST_F(HdfSerialsTest, Flush_001, TestSize.Level0)
{
    ASSERT_NE(serials_, nullptr);
    std::vector<SerialDeviceInfo> devices;
    int32_t ret = serials_->QueryDevices(devices);
    EXPECT_EQ(ret, HDF_SUCCESS);
    if (devices.empty()) {
        return;
    }

    sptr<SerialDeviceCallbackImpl> callback = new SerialDeviceCallbackImpl();
    sptr<ISerialDevice> device;
    ret = serials_->OpenDevice(devices[0].portName, defaultConfig_, callback, device);
    ASSERT_EQ(ret, HDF_SUCCESS);
    ASSERT_NE(device, nullptr);

    ret = device->Flush();
    EXPECT_EQ(ret, HDF_SUCCESS);

    device->Close();
}

HWTEST_F(HdfSerialsTest, Drain_001, TestSize.Level0)
{
    ASSERT_NE(serials_, nullptr);
    std::vector<SerialDeviceInfo> devices;
    int32_t ret = serials_->QueryDevices(devices);
    EXPECT_EQ(ret, HDF_SUCCESS);
    if (devices.empty()) {
        return;
    }

    sptr<SerialDeviceCallbackImpl> callback = new SerialDeviceCallbackImpl();
    sptr<ISerialDevice> device;
    ret = serials_->OpenDevice(devices[0].portName, defaultConfig_, callback, device);
    ASSERT_EQ(ret, HDF_SUCCESS);
    ASSERT_NE(device, nullptr);

    ret = device->Drain();
    EXPECT_EQ(ret, HDF_SUCCESS);

    device->Close();
}

HWTEST_F(HdfSerialsTest, SendBrkSignal_001, TestSize.Level0)
{
    ASSERT_NE(serials_, nullptr);
    std::vector<SerialDeviceInfo> devices;
    int32_t ret = serials_->QueryDevices(devices);
    EXPECT_EQ(ret, HDF_SUCCESS);
    if (devices.empty()) {
        return;
    }

    sptr<SerialDeviceCallbackImpl> callback = new SerialDeviceCallbackImpl();
    sptr<ISerialDevice> device;
    ret = serials_->OpenDevice(devices[0].portName, defaultConfig_, callback, device);
    ASSERT_EQ(ret, HDF_SUCCESS);
    ASSERT_NE(device, nullptr);

    ret = device->SendBrkSignal();
    EXPECT_EQ(ret, HDF_SUCCESS);

    device->Close();
}

HWTEST_F(HdfSerialsTest, SetRtsSignal_001, TestSize.Level0)
{
    ASSERT_NE(serials_, nullptr);
    std::vector<SerialDeviceInfo> devices;
    int32_t ret = serials_->QueryDevices(devices);
    EXPECT_EQ(ret, HDF_SUCCESS);
    if (devices.empty()) {
        return;
    }

    sptr<SerialDeviceCallbackImpl> callback = new SerialDeviceCallbackImpl();
    sptr<ISerialDevice> device;
    ret = serials_->OpenDevice(devices[0].portName, defaultConfig_, callback, device);
    ASSERT_EQ(ret, HDF_SUCCESS);
    ASSERT_NE(device, nullptr);

    ret = device->SetRtsSignal(true);
    EXPECT_EQ(ret, HDF_SUCCESS);

    ret = device->SetRtsSignal(false);
    EXPECT_EQ(ret, HDF_SUCCESS);

    device->Close();
}

HWTEST_F(HdfSerialsTest, GetCtsSignal_001, TestSize.Level0)
{
    ASSERT_NE(serials_, nullptr);
    std::vector<SerialDeviceInfo> devices;
    int32_t ret = serials_->QueryDevices(devices);
    EXPECT_EQ(ret, HDF_SUCCESS);
    if (devices.empty()) {
        return;
    }

    sptr<SerialDeviceCallbackImpl> callback = new SerialDeviceCallbackImpl();
    sptr<ISerialDevice> device;
    ret = serials_->OpenDevice(devices[0].portName, defaultConfig_, callback, device);
    ASSERT_EQ(ret, HDF_SUCCESS);
    ASSERT_NE(device, nullptr);

    bool cts = false;
    ret = device->GetCtsSignal(cts);
    EXPECT_EQ(ret, HDF_SUCCESS);

    device->Close();
}

HWTEST_F(HdfSerialsTest, CloseBeforeStopRead_001, TestSize.Level1)
{
    ASSERT_NE(serials_, nullptr);
    std::vector<SerialDeviceInfo> devices;
    int32_t ret = serials_->QueryDevices(devices);
    EXPECT_EQ(ret, HDF_SUCCESS);
    if (devices.empty()) {
        return;
    }

    sptr<SerialDeviceCallbackImpl> callback = new SerialDeviceCallbackImpl();
    sptr<ISerialDevice> device;
    ret = serials_->OpenDevice(devices[0].portName, defaultConfig_, callback, device);
    ASSERT_EQ(ret, HDF_SUCCESS);
    ASSERT_NE(device, nullptr);

    ret = device->StartRead();
    EXPECT_EQ(ret, HDF_SUCCESS);

    ret = device->Close();
    EXPECT_EQ(ret, HDF_SUCCESS);
}

HWTEST_F(HdfSerialsTest, OperationAfterClose_001, TestSize.Level1)
{
    ASSERT_NE(serials_, nullptr);
    std::vector<SerialDeviceInfo> devices;
    int32_t ret = serials_->QueryDevices(devices);
    EXPECT_EQ(ret, HDF_SUCCESS);
    if (devices.empty()) {
        return;
    }

    sptr<SerialDeviceCallbackImpl> callback = new SerialDeviceCallbackImpl();
    sptr<ISerialDevice> device;
    ret = serials_->OpenDevice(devices[0].portName, defaultConfig_, callback, device);
    ASSERT_EQ(ret, HDF_SUCCESS);
    ASSERT_NE(device, nullptr);

    device->Close();

    std::vector<uint8_t> data = {0x01, 0x02};
    int32_t bytesWritten = 0;
    ret = device->Write(data, TEST_WRITE_TIMEOUT_MS, bytesWritten);
    EXPECT_NE(ret, HDF_SUCCESS);

    ret = device->StartRead();
    EXPECT_NE(ret, HDF_SUCCESS);
}

HWTEST_F(HdfSerialsTest, DeviceOfflineCallback_001, TestSize.Level1)
{
    ASSERT_NE(serials_, nullptr);
    std::vector<SerialDeviceInfo> devices;
    int32_t ret = serials_->QueryDevices(devices);
    EXPECT_EQ(ret, HDF_SUCCESS);
    if (devices.empty()) {
        return;
    }

    sptr<SerialDeviceCallbackImpl> callback = new SerialDeviceCallbackImpl();
    sptr<ISerialDevice> device;
    ret = serials_->OpenDevice(devices[0].portName, defaultConfig_, callback, device);
    ASSERT_EQ(ret, HDF_SUCCESS);
    ASSERT_NE(device, nullptr);

    EXPECT_FALSE(callback->IsDeviceOffline());

    device->Close();
}

HWTEST_F(HdfSerialsTest, MultipleDevices_001, TestSize.Level1)
{
    ASSERT_NE(serials_, nullptr);
    std::vector<SerialDeviceInfo> devices;
    int32_t ret = serials_->QueryDevices(devices);
    EXPECT_EQ(ret, HDF_SUCCESS);
    if (devices.size() < TEST_MIN_DEVICES_COUNT) {
        return;
    }

    sptr<SerialDeviceCallbackImpl> callback1 = new SerialDeviceCallbackImpl();
    sptr<SerialDeviceCallbackImpl> callback2 = new SerialDeviceCallbackImpl();

    sptr<ISerialDevice> device1;
    ret = serials_->OpenDevice(devices[0].portName, defaultConfig_, callback1, device1);
    EXPECT_EQ(ret, HDF_SUCCESS);

    sptr<ISerialDevice> device2;
    ret = serials_->OpenDevice(devices[1].portName, defaultConfig_, callback2, device2);
    EXPECT_EQ(ret, HDF_SUCCESS);

    if (device1 != nullptr) {
        device1->Close();
    }
    if (device2 != nullptr) {
        device2->Close();
    }
}