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

#include <iostream>
#include <string>
#include <thread>
#include <atomic>
#include <mutex>
#include <condition_variable>
#include <queue>
#include <chrono>
#include <cstring>
#include <hdf_log.h>
#include "v1_0/iserials.h"
#include "v1_0/iserial_device_callback.h"

using namespace OHOS::HDI::Serials::V1_0;

constexpr int DEFAULT_BAUD_RATE = 115200;
constexpr int DEFAULT_DATA_BITS = 8;
constexpr int DEFAULT_STOP_BITS = 1;
constexpr int DEFAULT_PARITY = 0;
constexpr int DEFAULT_TIMEOUT = 1000;
constexpr int TEST_WAIT_DATA_TIMEOUT_MS = 1000;
constexpr int TEST_WAIT_OFFLINE_TIMEOUT_MS = 5000;
constexpr int TEST_READ_TIMEOUT_MS = 500;
constexpr int TEST_ECHO_READ_TIMEOUT_MS = 2000;
constexpr int TEST_PRINT_DATA_MAX_LEN = 64;
constexpr int TEST_SLEEP_TIME_MS = 100;
constexpr int TEST_ASCII_MIN = 32;
constexpr int TEST_ASCII_MAX = 126;
constexpr int MENU_CHOICE_MIN = 1;
constexpr int MENU_BAUD_RATE_MAX = 8;
constexpr int MENU_DATA_BITS_MAX = 4;
constexpr int MENU_STOP_BIT_TWO = 2;
constexpr int MENU_APPLY_CHOICE = 7;
constexpr int MENU_RESET_CHOICE = 8;
constexpr int MENU_EXIT_CHOICE = 0;

class SerialDeviceCallbackImpl : public ISerialDeviceCallback {
public:
    SerialDeviceCallbackImpl() : deviceOffline_(false) {}
    ~SerialDeviceCallbackImpl() override = default;

    int32_t OnDeviceOffline() override
    {
        deviceOffline_ = true;
        offlineCond_.notify_all();
        std::cout << "\n[Device offline detected]\n";
        return HDF_SUCCESS;
    }

    int32_t OnReadData(const std::vector<int8_t>& data, uint32_t dataLen) override
    {
        std::lock_guard<std::mutex> lock(dataMutex_);
        receivedData_.push({data, dataLen});
        dataCond_.notify_one();
        return HDF_SUCCESS;
    }

    bool WaitForData(std::vector<int8_t>& data, uint32_t& dataLen, int timeoutMs = TEST_WAIT_DATA_TIMEOUT_MS)
    {
        std::unique_lock<std::mutex> lock(dataMutex_);
        if (dataCond_.wait_for(lock, std::chrono::milliseconds(timeoutMs),
            [this] { return !receivedData_.empty(); })) {
            auto front = receivedData_.front();
            receivedData_.pop();
            data = front.first;
            dataLen = front.second;
            return true;
        }
        return false;
    }

    bool WaitForOffline(int timeoutMs = TEST_WAIT_OFFLINE_TIMEOUT_MS)
    {
        std::unique_lock<std::mutex> lock(offlineMutex_);
        return offlineCond_.wait_for(lock, std::chrono::milliseconds(timeoutMs),
            [this] { return deviceOffline_.load(); });
    }

    bool IsDeviceOffline() const { return deviceOffline_.load(); }

    void ClearBuffer()
    {
        std::lock_guard<std::mutex> lock(dataMutex_);
        while (!receivedData_.empty()) {
            receivedData_.pop();
        }
    }

    void Reset() { deviceOffline_.store(false); }

private:
    std::atomic<bool> deviceOffline_;
    std::mutex dataMutex_;
    std::mutex offlineMutex_;
    std::condition_variable dataCond_;
    std::condition_variable offlineCond_;
    std::queue<std::pair<std::vector<int8_t>, uint32_t>> receivedData_;
};

class SerialConfigMenu {
public:
    void DisplayMenu()
    {
        std::cout << "\n========== Serial Configuration Menu ==========\n";
        std::cout << "1. Baud Rate (current: " << config_.baudRate << ")\n";
        std::cout << "2. Data Bits (current: " << config_.dataBits << ")\n";
        std::cout << "3. Stop Bits (current: " << config_.stopBits << ")\n";
        std::cout << "4. Parity (current: " << GetParityString(config_.parity) << ")\n";
        std::cout << "5. RTS/CTS (current: " << (config_.rtscts ? "On" : "Off") << ")\n";
        std::cout << "6. XON/XOFF (current: " << (config_.xon ? "On" : "Off") << ")\n";
        std::cout << "7. Apply\n8. Reset\n0. Exit\n";
        std::cout << "================================================\n";
    }

    void HandleMenuChoice(int choice)
    {
        switch (choice) {
            case 1: ConfigureBaudRate(); break;
            case 2: ConfigureDataBits(); break;
            case 3: ConfigureStopBits(); break;
            case 4: ConfigureParity(); break;
            case 5: ConfigureRtsCts(); break;
            case 6: ConfigureXonXoff(); break;
            case 7: ApplyConfig(); break;
            case 8: ResetToDefaults(); break;
            default: break;
        }
    }

    SerialConfig GetConfig() const { return config_; }
    void SetConfig(const SerialConfig& config) { config_ = config; }

    void ConfigureBaudRate()
    {
        std::cout << "\nSelect Baud Rate:\n";
        std::cout << "1.9600 2.19200 3.38400 4.57600 5.115200 6.230400 7.460800 8.921600\n";
        int choice;
        std::cin >> choice;
        int rates[] = {9600, 19200, 38400, 57600, 115200, 230400, 460800, 921600};
        config_.baudRate = (choice >= MENU_CHOICE_MIN && choice <= MENU_BAUD_RATE_MAX) ?
            rates[choice - MENU_CHOICE_MIN] : DEFAULT_BAUD_RATE;
        std::cout << "Baud rate set to: " << config_.baudRate << "\n";
    }

    void ConfigureDataBits()
    {
        std::cout << "\nSelect Data Bits: 1.5 2.6 3.7 4.8\n";
        int choice;
        std::cin >> choice;
        config_.dataBits = (choice >= MENU_CHOICE_MIN && choice <= MENU_DATA_BITS_MAX) ?
            choice + MENU_DATA_BITS_MAX : DEFAULT_DATA_BITS;
        std::cout << "Data bits set to: " << config_.dataBits << "\n";
    }

    void ConfigureStopBits()
    {
        std::cout << "\nSelect Stop Bits: 1.1 2.2\n";
        int choice;
        std::cin >> choice;
        config_.stopBits = (choice == MENU_STOP_BIT_TWO) ? MENU_STOP_BIT_TWO : DEFAULT_STOP_BITS;
        std::cout << "Stop bits set to: " << config_.stopBits << "\n";
    }

    void ConfigureParity()
    {
        std::cout << "\nSelect Parity: 0.None 1.Odd 2.Even\n";
        int choice;
        std::cin >> choice;
        config_.parity = (choice >= 0 && choice <= 2) ? choice : 0;
        std::cout << "Parity set to: " << GetParityString(config_.parity) << "\n";
    }

    void ConfigureRtsCts()
    {
        std::cout << "\nRTS/CTS: 0.Off 1.On\n";
        int choice;
        std::cin >> choice;
        config_.rtscts = (choice == 1);
        std::cout << "RTS/CTS: " << (config_.rtscts ? "On" : "Off") << "\n";
    }

    void ConfigureXonXoff()
    {
        std::cout << "\nXON/XOFF: 0.Off 1.XON 2.XOFF 3.XANY\n";
        int choice;
        std::cin >> choice;
        config_.xon = (choice == 1);
        config_.xoff = (choice == 2);
        config_.xany = (choice == 3);
    }

    void ApplyConfig() { std::cout << "Configuration applied.\n"; }

    void ResetToDefaults()
    {
        config_.baudRate = DEFAULT_BAUD_RATE;
        config_.dataBits = DEFAULT_DATA_BITS;
        config_.stopBits = DEFAULT_STOP_BITS;
        config_.parity = DEFAULT_PARITY;
        config_.rtscts = false;
        config_.xon = false;
        config_.xoff = false;
        config_.xany = false;
        std::cout << "Configuration reset to defaults.\n";
    }

    std::string GetParityString(int parity) const
    {
        const char* names[] = {"None", "Odd", "Even"};
        return (parity >= 0 && parity <= 2) ? names[parity] : "Unknown";
    }
private:
    SerialConfig config_ = {DEFAULT_BAUD_RATE, DEFAULT_DATA_BITS, DEFAULT_STOP_BITS,
        DEFAULT_PARITY, false, false, false, false};
};

class SerialSampleTest {
public:
    SerialSampleTest() : running_(false), readThreadRunning_(false) {}
    ~SerialSampleTest() { StopReadThread(); CloseDevice(); }

    bool Init()
    {
        serials_ = ISerials::Get(true);
        if (serials_ == nullptr) {
            std::cout << "Failed to get serial service.\n";
            return false;
        }
        std::cout << "Serial service initialized.\n";
        return true;
    }

    bool QueryDevices()
    {
        if (serials_ == nullptr) {
            std::cout << "Service not initialized.\n";
            return false;
        }

        std::vector<SerialDeviceInfo> devices;
        int32_t ret = serials_->QueryDevices(devices);
        if (ret != HDF_SUCCESS) {
            std::cout << "QueryDevices failed.\n";
            return false;
        }

        if (devices.empty()) {
            std::cout << "No devices found.\n";
            return true;
        }

        PrintDeviceList(devices);
        devices_ = devices;
        return true;
    }

    bool OpenDevice(int deviceIndex, const SerialConfig& config)
    {
        if (serials_ == nullptr || devices_.empty()) {
            std::cout << "No devices available.\n";
            return false;
        }

        if (deviceIndex < 0 || deviceIndex >= static_cast<int>(devices_.size())) {
            deviceIndex = 0;
        }

        if (device_ != nullptr) {
            std::cout << "Device already open.\n";
            return false;
        }

        callback_ = new SerialDeviceCallbackImpl();
        std::string portName = devices_[deviceIndex].portName;
        int32_t ret = serials_->OpenDevice(portName, config, callback_, device_);
        if (ret != HDF_SUCCESS) {
            std::cout << "OpenDevice failed.\n";
            callback_ = nullptr;
            return false;
        }

        std::cout << "Device opened: " << portName << "\n";
        return true;
    }

    void CloseDevice()
    {
        StopReadThread();
        if (device_ != nullptr) {
            device_->Close();
            device_ = nullptr;
            std::cout << "Device closed.\n";
        }
        callback_ = nullptr;
    }

    bool WriteData(const std::vector<uint8_t>& data)
    {
        if (device_ == nullptr) {
            std::cout << "Device not open.\n";
            return false;
        }

        int32_t bytesWritten = 0;
        int32_t ret = device_->Write(data, DEFAULT_TIMEOUT, bytesWritten);
        if (ret != HDF_SUCCESS) {
            std::cout << "Write failed.\n";
            return false;
        }
        std::cout << "Written " << bytesWritten << " bytes.\n";
        return true;
    }

    bool ReadData(std::vector<int8_t>& data, uint32_t& dataLen, int timeoutMs = 1000)
    {
        if (callback_ == nullptr) {
            return false;
        }
        return callback_->WaitForData(data, dataLen, timeoutMs);
    }

    void StartReadThread()
    {
        if (device_ == nullptr || readThreadRunning_) {
            return;
        }

        int32_t ret = device_->StartRead();
        if (ret != HDF_SUCCESS) {
            std::cout << "StartRead failed.\n";
            return;
        }

        readThreadRunning_ = true;
        running_ = true;
        readThread_ = std::thread(&SerialSampleTest::ReadThreadFunc, this);
        std::cout << "Read thread started.\n";
    }

    void StopReadThread()
    {
        if (!readThreadRunning_) {
            return;
        }

        running_ = false;
        if (device_ != nullptr) {
            device_->StopRead();
        }
        if (readThread_.joinable()) {
            readThread_.join();
        }
        readThreadRunning_ = false;
        std::cout << "Read thread stopped.\n";
    }

    bool Flush()
    {
        if (device_ == nullptr) {
            return false;
        }
        return device_->Flush() == HDF_SUCCESS;
    }

    bool Drain()
    {
        if (device_ == nullptr) {
            return false;
        }
        return device_->Drain() == HDF_SUCCESS;
    }

    bool SendBreak()
    {
        if (device_ == nullptr) {
            return false;
        }
        return device_->SendBrkSignal() == HDF_SUCCESS;
    }

    bool SetRts(bool rts)
    {
        if (device_ == nullptr) {
            return false;
        }
        return device_->SetRtsSignal(rts) == HDF_SUCCESS;
    }

    bool GetCts(bool& cts)
    {
        if (device_ == nullptr) {
            return false;
        }
        return device_->GetCtsSignal(cts) == HDF_SUCCESS;
    }

    bool IsDeviceOpen() const { return device_ != nullptr; }
    bool IsReadThreadRunning() const { return readThreadRunning_; }
    bool IsDeviceOffline() const { return callback_ != nullptr && callback_->IsDeviceOffline(); }

    void PrintDeviceList(const std::vector<SerialDeviceInfo>& devices)
    {
        std::cout << "\n========== Available Devices ==========\n";
        for (size_t i = 0; i < devices.size(); ++i) {
            std::cout << i << ": " << devices[i].portName << " (" << devices[i].manufacturer << ")\n";
        }
        std::cout << "========================================\n";
    }

    void ReadThreadFunc()
    {
        std::cout << "Read thread waiting for data...\n";
        while (running_ && !IsDeviceOffline()) {
            std::vector<int8_t> data;
            uint32_t dataLen = 0;
            if (ReadData(data, dataLen, TEST_READ_TIMEOUT_MS)) {
                PrintReceivedData(data, dataLen);
            }
        }
        std::cout << "Read thread exiting.\n";
    }

    void PrintReceivedData(const std::vector<int8_t>& data, uint32_t dataLen)
    {
        std::cout << "\n[Received " << dataLen << " bytes]: ";
        for (size_t i = 0; i < data.size() && i < TEST_PRINT_DATA_MAX_LEN; ++i) {
            char c = static_cast<char>(data[i]);
            std::cout << (c >= TEST_ASCII_MIN && c <= TEST_ASCII_MAX ? c : '.');
        }
        std::cout << "\n";
    }
private:
    sptr<ISerials> serials_ = nullptr;
    sptr<ISerialDevice> device_ = nullptr;
    sptr<SerialDeviceCallbackImpl> callback_ = nullptr;
    std::vector<SerialDeviceInfo> devices_;
    std::atomic<bool> running_;
    std::atomic<bool> readThreadRunning_;
    std::thread readThread_;
};

void DisplayMainMenu()
{
    std::cout << "\n========== Serial Sample Test ==========\n";
    std::cout << "1.Init 2.Query 3.Config 4.Open 5.Close\n";
    std::cout << "6.StartRead 7.StopRead 8.Write 9.Flush\n";
    std::cout << "10.Drain 11.Break 12.RTS 13.CTS 14.Echo 0.Exit\n";
    std::cout << "========================================\n";
}

void RunEchoTest(SerialSampleTest& test)
{
    std::cout << "\nEnter data to send: ";
    std::string input;
    std::cin.ignore();
    std::getline(std::cin, input);
    if (input == "quit") {
        return;
    }

    std::vector<uint8_t> data(input.begin(), input.end());
    if (test.WriteData(data)) {
        std::this_thread::sleep_for(std::chrono::milliseconds(TEST_SLEEP_TIME_MS));
        std::vector<int8_t> received;
        uint32_t dataLen = 0;
        if (test.ReadData(received, dataLen, TEST_ECHO_READ_TIMEOUT_MS)) {
            std::cout << "Echo: ";
            for (auto byte : received) {
                std::cout << static_cast<char>(byte);
            }
            std::cout << "\n";
        } else {
            std::cout << "No echo (timeout).\n";
        }
    }
}

void HandleConfigMenu(SerialConfigMenu& configMenu, SerialConfig& currentConfig, bool& configReady)
{
    int configChoice;
    do {
        configMenu.DisplayMenu();
        std::cout << "Choice: ";
        std::cin >> configChoice;
        if (configChoice == MENU_APPLY_CHOICE) {
            currentConfig = configMenu.GetConfig();
            configReady = true;
        } else if (configChoice == MENU_RESET_CHOICE) {
            configMenu.ResetToDefaults();
        }
        configMenu.HandleMenuChoice(configChoice);
    } while (configChoice != MENU_EXIT_CHOICE);
}

void HandleOpenDevice(SerialSampleTest& test, const SerialConfig& currentConfig,
    bool configReady, SerialConfigMenu& configMenu)
{
    int deviceIndex = 0;
    std::cout << "Device index (default 0): ";
    std::cin >> deviceIndex;

    SerialConfig config = configReady ? currentConfig : configMenu.GetConfig();
    test.OpenDevice(deviceIndex, config);
}

void HandleWriteData(SerialSampleTest& test)
{
    std::string data;
    std::cout << "Data to write: ";
    std::cin.ignore();
    std::getline(std::cin, data);
    test.WriteData(std::vector<uint8_t>(data.begin(), data.end()));
}

void HandleRtsSignal(SerialSampleTest& test)
{
    int rtsChoice;
    std::cout << "RTS (0=low, 1=high): ";
    std::cin >> rtsChoice;
    test.SetRts(rtsChoice == 1);
}

void HandleCtsSignal(SerialSampleTest& test)
{
    bool cts = false;
    if (test.GetCts(cts)) {
        std::cout << "CTS: " << (cts ? "high" : "low") << "\n";
    }
}

void HandleEchoTest(SerialSampleTest& test)
{
    if (!test.IsDeviceOpen()) {
        std::cout << "Please open device first.\n";
        return;
    }
    if (!test.IsReadThreadRunning()) {
        test.StartReadThread();
        std::this_thread::sleep_for(std::chrono::milliseconds(TEST_SLEEP_TIME_MS));
    }
    RunEchoTest(test);
}

void ProcessUserChoice(int choice, SerialSampleTest& test, SerialConfigMenu& configMenu,
    SerialConfig& currentConfig, bool& configReady)
{
    switch (choice) {
        case MENU_CHOICE_MIN: test.Init(); break;
        case 2: test.QueryDevices(); break;
        case 3: HandleConfigMenu(configMenu, currentConfig, configReady); break;
        case 4: HandleOpenDevice(test, currentConfig, configReady, configMenu); break;
        case 5: test.CloseDevice(); break;
        case 6: test.StartReadThread(); break;
        case 7: test.StopReadThread(); break;
        case 8: HandleWriteData(test); break;
        case 9: test.Flush(); break;
        case 10: test.Drain(); break;
        case 11: test.SendBreak(); break;
        case 12: HandleRtsSignal(test); break;
        case 13: HandleCtsSignal(test); break;
        case 14: HandleEchoTest(test); break;
        default: break;
    }
}

int main()
{
    SerialSampleTest test;
    SerialConfigMenu configMenu;
    SerialConfig currentConfig;
    bool configReady = false;


    while (true) {
        DisplayMainMenu();
        std::cout << "Choice: ";
        int choice;
        std::cin >> choice;

        if (choice == MENU_EXIT_CHOICE) {
            std::cout << "Exiting...\n";
            return MENU_EXIT_CHOICE;
        }

        ProcessUserChoice(choice, test, configMenu, currentConfig, configReady);

        if (test.IsDeviceOffline()) {
            std::cout << "\nDevice offline. Please reopen.\n";
        }
    }

    return MENU_EXIT_CHOICE;
}