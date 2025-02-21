/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "usbd_serial_test.h"

#include "v1_0/iserial_interface.h"
#include "v1_0/serial_types.h"

using namespace testing::ext;
using namespace OHOS::HDI::Usb::Serial::V1_0;

#define ERR_CODE_IOEXCEPTION (-5)
#define ERR_CODE_DEVICENOTOPEN (-6)
#define ERR_CODE_TIMED_OUT (-7)

constexpr int32_t VALID_PORTID = 0;
constexpr int32_t INVALID_PORTID = -1;
constexpr int32_t OK = 0;
constexpr int32_t ONE_KBYTE = 1024;
constexpr int32_t ONE_SECOND = 1000;
constexpr int32_t MAX_MEMORY = 8192;
static std::vector<OHOS::HDI::Usb::Serial::V1_0::SerialPort> g_portList;

template<typename T>
std::shared_ptr<T> make_shared_array(size_t size)
{
    if (size == 0) {
        return NULL;
    }
    if (size > MAX_MEMORY) {
        return NULL;
    }
    T* buffer = new (std::nothrow)T[size];
    if (!buffer) {
        return NULL;
    }
    return std::shared_ptr<T>(buffer, [] (T* p) { delete[] p; });
}

namespace OHOS {
namespace SERIAL {
sptr<OHOS::HDI::Usb::Serial::V1_0::ISerialInterface> g_serialInterface = nullptr;

void SerialTest::SetUpTestCase(void)
{
    g_serialInterface = OHOS::HDI::Usb::Serial::V1_0::ISerialInterface::Get("serial_interface_service", true);
    if (g_serialInterface == nullptr) {
        printf("NULL\n");
        exit(0);
    }
    std::cout << "请先插拔串口线，输入回车继续" << std::endl;
    char c;
    scanf("%c", &c);
    g_serialInterface->SerialGetPortList(g_portList);
}

void SerialTest::TearDownTestCase(void) {}

void SerialTest::SetUp(void) {}

void SerialTest::TearDown(void) {}

/**
 * @tc.name: SerialGetPortList_001
 * @tc.desc: Test functions to int32_t SerialGetPortList(std::vector<OHOS::HDI::Usb::Serial::V1_0::SerialPort>&
 *           portList)
 * @tc.type: FUNC
 */
HWTEST_F(SerialTest, SerialGetPortList_001, TestSize.Level1)
{
    EXPECT_NE(g_portList.size(), 0);
    EXPECT_EQ(g_portList[0].portId, VALID_PORTID);
}

/**
 * @tc.name: SerialOpen_001
 * @tc.desc: Test functions to int32_t SerialOpen(int32_t portId)
 * @tc.type: FUNC
 */
HWTEST_F(SerialTest, SerialOpen_001, TestSize.Level1)
{
    g_serialInterface->SerialClose(VALID_PORTID);
    EXPECT_EQ(g_serialInterface->SerialOpen(VALID_PORTID), OK);
    g_serialInterface->SerialClose(VALID_PORTID);
}

/**
 * @tc.name: SerialOpen_002
 * @tc.desc: Test functions to int32_t SerialOpen(int32_t portId)
 * @tc.type: FUNC
 */
HWTEST_F(SerialTest, SerialOpen_002, TestSize.Level1)
{
    g_serialInterface->SerialClose(INVALID_PORTID);
    EXPECT_NE(g_serialInterface->SerialOpen(INVALID_PORTID), OK);
    g_serialInterface->SerialClose(INVALID_PORTID);
}

/**
 * @tc.name: SerialWrite_001
 * @tc.desc: Test functions to int32_t SerialWrite(int32_t portId, const std::vector<uint8_t> &data,
 *           uint32_t size, uint32_t timeout)
 * @tc.type: FUNC
 */
HWTEST_F(SerialTest, SerialWrite_001, TestSize.Level1)
{
    g_serialInterface->SerialClose(VALID_PORTID);
    g_serialInterface->SerialOpen(VALID_PORTID);
    std::vector<uint8_t> data = { 't', 'e', 's', 't' };
    int32_t ret = g_serialInterface->SerialWrite(VALID_PORTID, data, data.size(), 0);
    EXPECT_EQ(ret, OK);
    g_serialInterface->SerialClose(VALID_PORTID);
}

/**
 * @tc.name: SerialWrite_002
 * @tc.desc: Test functions to int32_t SerialWrite(int32_t portId, const std::vector<uint8_t> &data,
 *           uint32_t size, uint32_t timeout)
 * @tc.type: FUNC
 */
HWTEST_F(SerialTest, SerialWrite_002, TestSize.Level1)
{
    g_serialInterface->SerialClose(INVALID_PORTID);
    g_serialInterface->SerialOpen(INVALID_PORTID);
    std::vector<uint8_t> data = { 't', 'e', 's', 't' };
    int32_t ret = g_serialInterface->SerialWrite(INVALID_PORTID, data, data.size(), 0);
    EXPECT_EQ(ret, ERR_CODE_IOEXCEPTION);
    g_serialInterface->SerialClose(INVALID_PORTID);
}

/**
 * @tc.name: SerialRead_001
 * @tc.desc: Test functions to int32_t SerialRead(int32_t portId, uint8_t *data,
 *           uint32_t size, uint32_t timeout)
 * @tc.type: FUNC
 */
HWTEST_F(SerialTest, SerialRead_001, TestSize.Level1)
{
    g_serialInterface->SerialClose(VALID_PORTID);
    g_serialInterface->SerialOpen(VALID_PORTID);
    std::vector<uint8_t> data;
    int32_t ret = g_serialInterface->SerialRead(VALID_PORTID, data, ONE_KBYTE, ONE_SECOND);
    EXPECT_EQ(ret, ERR_CODE_TIMED_OUT);
    g_serialInterface->SerialClose(VALID_PORTID);
}

/**
 * @tc.name: SerialRead_002
 * @tc.desc: Test functions to int32_t SerialRead(int32_t portId, uint8_t *data,
 *           uint32_t size, uint32_t timeout)
 * @tc.type: FUNC
 */
HWTEST_F(SerialTest, SerialRead_002, TestSize.Level1)
{
    g_serialInterface->SerialClose(INVALID_PORTID);
    g_serialInterface->SerialOpen(INVALID_PORTID);
    std::vector<uint8_t> data;
    int32_t ret = g_serialInterface->SerialRead(INVALID_PORTID, data, ONE_KBYTE, 0);
    EXPECT_EQ(ret, ERR_CODE_IOEXCEPTION);
    g_serialInterface->SerialClose(INVALID_PORTID);
}

/**
 * @tc.name: SerialRead_003
 * @tc.desc: Test functions to int32_t SerialRead(int32_t portId, uint8_t *data,
 *           uint32_t size, uint32_t timeout)
 * @tc.type: FUNC
 */
HWTEST_F(SerialTest, SerialRead_003, TestSize.Level1)
{
    g_serialInterface->SerialClose(VALID_PORTID);
    g_serialInterface->SerialOpen(VALID_PORTID);
    std::cout << "请打开串口工具单次发送数据，输入回车继续" << std::endl;
    char c;
    scanf("%c", &c);
    std::vector<uint8_t> data;
    int32_t ret = g_serialInterface->SerialRead(VALID_PORTID, data, ONE_KBYTE, 0);
    EXPECT_EQ(ret, 0);
    g_serialInterface->SerialClose(VALID_PORTID);
}

/**
 * @tc.name: SerialGetAttribute_001
 * @tc.desc: Test functions to int32_t SerialGetAttribute(int32_t portId,
 *           OHOS::HDI::Usb::Serial::V1_0::SerialAttribute& attributeInfo)
 * @tc.type: FUNC
 */
HWTEST_F(SerialTest, SerialGetAttribute_001, TestSize.Level1)
{
    g_serialInterface->SerialClose(VALID_PORTID);
    g_serialInterface->SerialOpen(VALID_PORTID);
    OHOS::HDI::Usb::Serial::V1_0::SerialAttribute attributeInfo;
    int32_t ret = g_serialInterface->SerialGetAttribute(VALID_PORTID, attributeInfo);
    EXPECT_EQ(ret, OK);
    g_serialInterface->SerialClose(VALID_PORTID);
}

/**
 * @tc.name: SerialGetAttribute_002
 * @tc.desc: Test functions to int32_t SerialGetAttribute(int32_t portId,
 *           OHOS::HDI::Usb::Serial::V1_0::SerialAttribute& attributeInfo)
 * @tc.type: FUNC
 */
HWTEST_F(SerialTest, SerialGetAttribute_002, TestSize.Level1)
{
    g_serialInterface->SerialClose(INVALID_PORTID);
    g_serialInterface->SerialOpen(INVALID_PORTID);
    OHOS::HDI::Usb::Serial::V1_0::SerialAttribute attributeInfo;
    int32_t ret = g_serialInterface->SerialGetAttribute(INVALID_PORTID, attributeInfo);
    EXPECT_NE(ret, OK);
    g_serialInterface->SerialClose(INVALID_PORTID);
}

/**
 * @tc.name: SerialSetAttribute_001
 * @tc.desc: Test functions to int32_t SerialSetAttribute(int32_t portId,
 *           const OHOS::HDI::Usb::Serial::V1_0::SerialAttribute& attributeInfo)
 * @tc.type: FUNC
 */
HWTEST_F(SerialTest, SerialSetAttribute_001, TestSize.Level1)
{
    g_serialInterface->SerialClose(VALID_PORTID);
    g_serialInterface->SerialOpen(VALID_PORTID);
    OHOS::HDI::Usb::Serial::V1_0::SerialAttribute attributeInfo;
    attributeInfo.baudrate = OHOS::HDI::Usb::Serial::V1_0::BAUDRATE_576000;
    attributeInfo.dataBits = OHOS::HDI::Usb::Serial::V1_0::USB_ATTR_DATABIT_6;
    attributeInfo.parity = OHOS::HDI::Usb::Serial::V1_0::USB_ATTR_PARITY_ODD;
    attributeInfo.stopBits = OHOS::HDI::Usb::Serial::V1_0::USB_ATTR_STOPBIT_2;
    int32_t ret = g_serialInterface->SerialSetAttribute(VALID_PORTID, attributeInfo);
    EXPECT_EQ(ret, OK);
    g_serialInterface->SerialClose(VALID_PORTID);
}

/**
 * @tc.name: SerialSetAttribute_002
 * @tc.desc: Test functions to int32_t SerialSetAttribute(int32_t portId,
 *           const OHOS::HDI::Usb::Serial::V1_0::SerialAttribute& attributeInfo)
 * @tc.type: FUNC
 */
HWTEST_F(SerialTest, SerialSetAttribute_002, TestSize.Level1)
{
    g_serialInterface->SerialClose(INVALID_PORTID);
    g_serialInterface->SerialOpen(INVALID_PORTID);
    OHOS::HDI::Usb::Serial::V1_0::SerialAttribute attributeInfo;
    attributeInfo.baudrate = OHOS::HDI::Usb::Serial::V1_0::BAUDRATE_576000;
    attributeInfo.dataBits = OHOS::HDI::Usb::Serial::V1_0::USB_ATTR_DATABIT_6;
    attributeInfo.parity = OHOS::HDI::Usb::Serial::V1_0::USB_ATTR_PARITY_ODD;
    attributeInfo.stopBits = OHOS::HDI::Usb::Serial::V1_0::USB_ATTR_STOPBIT_2;
    int32_t ret = g_serialInterface->SerialSetAttribute(INVALID_PORTID, attributeInfo);
    EXPECT_NE(ret, OK);
    g_serialInterface->SerialClose(INVALID_PORTID);
}

/**
 * @tc.name: SerialClose_001
 * @tc.desc: Test functions to int32_t SerialClose(int32_t portId)
 * @tc.type: FUNC
 */
HWTEST_F(SerialTest, SerialClose_001, TestSize.Level1)
{
    g_serialInterface->SerialClose(VALID_PORTID);
    g_serialInterface->SerialOpen(VALID_PORTID);
    EXPECT_EQ(g_serialInterface->SerialClose(VALID_PORTID), OK);
    g_serialInterface->SerialClose(VALID_PORTID);
}

}
}