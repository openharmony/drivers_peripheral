# ClearPlay

## 概述

OpenHarmony ClearPlay驱动对上实现媒体版权保护（DRM）的HDI（Hardware Device Interface）接口，
为DRM框架提供DRM版权保护的具体实现；作为DRM插件适配样例，指导用户适配其他产商的DRM插件。 

## 目录

- ClearPlay模块目录表如下：

  ```
/drivers/peripheral/ClearPlay
├── bundle.json                   # ClearPlay驱动构建脚本
├── hdi_service                   # ClearPlay驱动服务功能实现代码
│   ├── common                    # ClearPlay驱动服务依赖的工具类代码，包含json解析、base64编解码
│   ├── include                   # ClearPlay驱动服务头文件
│   └── src                       # ClearPlay驱动服务具体实现代码
├── interfaces                    # ClearPlay驱动能力接口
│   ├── include                   # ClearPlay驱动能力接口头文件
│   └── src                       # ClearPlay驱动能力接口实现
└── test                          # ClearPlay驱动测试代码
    ├── sample                    # ClearPlay驱动功能验证demo
    │   ├── include               # ClearPlay驱动功能验证demo头文件
    │   └── src                   # ClearPlay驱动功能验证demo具体实现
    └── unittest                  # ClearPlay驱动UT用例
        ├── include               # ClearPlay驱动UT用例头文件
        └── src                   # ClearPlay驱动UT用例实现
  ```  

## ClearPlay驱动能力接口说明

- imedia_key_system_factory.h

  | 功能描述                         | 接口名称                                                     |
  | -------------------------------- | ------------------------------------------------------------ |
  | 查询设备是否支持uuid/媒体类型/安全级别对应的插件     | int32_t IsMediaKeySystemSupported(const std::string& uuid, const std::string& mimeType, ContentProtectionLevel level, bool& isSupported) |
  | 创建MediaKeySysem对象                             | int32_t CreateMediaKeySystem(sptr<OHOS::HDI::Drm::V1_0::IMediaKeySystem>& mediaKeySystem) |
  | 获取插件版本                                      | int32_t GetVersion(uint32_t& majorVer, uint32_t& minorVer) |
 

 - imedia_key_system.h

  | 功能描述                         | 接口名称                                                     |
  | -------------------------------- | ------------------------------------------------------------ |
  | 根据配置类型和属性名获取对应配置值，包括输出保护状态、设备属性、支持的最大会话数、当前会话数     | int32_t GetConfigurationString(const std::string& name, std::string& value)  |
  | 根据配置类型和属性名设置对应配置值                           | int32_t SetConfigurationString(const std::string& name, const std::string& value) |
  | 根据配置类型和属性名获取对应配置值，包括输出保护状态、设备属性、支持的最大会话数、当前会话数                          | int32_t GetConfigurationByteArray(const std::string& name, std::vector<uint8_t>& value) |
  | 根据配置类型和属性名设置对应配置值                           | int32_t SetConfigurationByteArray(const std::string& name, const std::vector<uint8_t>& value) |
  | 获取DRM度量值                                              | int32_t GetMetrics(std::map<std::string, std::string>& metrics) |
  | 获取MediaKeySystem最大安全级别                              | int32_t GetMaxContentProtectionLevel(ContentProtectionLevel& level) |
  | 生成设备证书获取请求                                        | int32_t GenerateKeySystemRequest(std::string& defaultUrl, std::vector<uint8_t>& request) |
  | 解析设备证书获取响应                                        | int32_t ProcessKeySystemResponse(const std::vector<uint8_t>& response) |
  | 获取证书状态                                               | int32_t GetOemCertificateStatus(CertificateStatus& status) |
  | 注册和取消注册MediaKeySystem监听时事件                      | int32_t SetCallback(const sptr<OHOS::HDI::Drm::V1_0::IMediaKeySystemCallback>& callback) |
  | 根据安全级别创建会话                                        | int32_t CreateMediaKeySession(ContentProtectionLevel level,
  sptr<OHOS::HDI::Drm::V1_0::IMediaKeySession>& keySession) |
  | 创建会话                                                   | int32_t CreateMediaKeySessionDefault(sptr<OHOS::HDI::Drm::V1_0::IMediaKeySession>& keySession) |
  | 获取所有离线密钥或密钥组索引                                 | int32_t GetOfflineMediaKeyIds(std::vector<std::vector<uint8_t>>& mediakeyIds) |
  | 获取所有离线密钥或密钥组索引                                 | int32_t GetOfflineMediaKeyIds(std::vector<std::vector<uint8_t>>& mediakeyIds) |
  | 获取指定离线密钥或密钥组状态                                 | int32_t GetOfflineMediaKeyStatus(const std::vector<uint8_t>& mediakeyId, OfflineMediaKeyStatus& mediakeyStatus) |
  | 获取OEM证书                                                | int32_t GetOemCertificate(sptr<OHOS::HDI::Drm::V1_0::IOemCertificate>& oemCert) |
  | 释放MediaKeySystem                                         | int32_t Destroy() |


 - ikey_session.h

  | 功能描述                         | 接口名称                                                     |
  | -------------------------------- | ------------------------------------------------------------ |
  | 生成一个许可证获取请求             | int32_t GenerateMediaKeyRequest(const MediaKeyRequestInfo& mediakeyRequestInfo,
  MediaKeyRequest& mediakeyRequest) |
  | 解析许可证获取响应                 | int32_t ProcessMediaKeyResponse(const std::vector<uint8_t>& mediakeyResponse, std::vector<uint8_t>& mediakeyId) | 
  | 检查当前会话的许可证状态            | int32_t CheckMediaKeyStatus(std::map<std::string, OHOS::HDI::Drm::V1_0::MediaKeySessionKeyStatus>& mediakeyStatus) |
  | 移除当前会话下所有许可证            | int32_t RemoveMediaKey() |
  | 生成离线密钥释放请求                | int32_t GetOfflineReleaseRequest(const std::vector<uint8_t>& mediakeyId, std::vector<uint8_t>& releaseRequest) |
  | 解析离线密钥释放响应                | int32_t ProcessOfflineReleaseResponse(const std::vector<uint8_t>& mediakeyId, const std::vector<uint8_t>& response) |
  | 恢复离线密钥和密钥组，并加载到当前会话中                           | int32_t RestoreOfflineMediaKey(const std::vector<uint8_t>& mediakeyId) |
  | 获取KeySession安全级别              | int32_t GetContentProtectionLevel(ContentProtectionLevel& level) |
  | 查询是否支持安全解码                 | int32_t RequiresSecureDecoderModule(const std::string& mimeType, bool& required) |
  | 注册和取消注册监听事件               | int32_t SetCallback(const sptr<OHOS::HDI::Drm::V1_0::IMediaKeySessionCallback>& callback) |
  | 获取解密模块                        | int32_t GetMediaDecryptModule(sptr<OHOS::HDI::Drm::V1_0::IMediaDecryptModule>& decryptModule) |
  | 释放当前会话                        | int32_t Destroy() |


 - imedia_decrypt_module.h

  | 功能描述                         | 接口名称                                                     |
  | -------------------------------- | ------------------------------------------------------------ |
  | 解密媒体数据     | int32_t DecryptMediaData(bool secure, const AVBuffer& srcBuffer, const AVBuffer& destBuffer) |
  | 解密模块资源释放  | int32_t Release() |


 - ikey_session_callback.h

  | 功能描述                       | 接口名称                                                     |
  | ------------------------------| ------------------------------------------------------------ |
  | HDI MediaKeySession事件监听接口                  | int32_t SendEvent(EventType eventType, int32_t extra, const std::vector<uint8_t>& data) |
  | HDI MediaKeySession事件监听接口，密钥状态改变     | int32_t SendEventKeyChange(const std::map<std::vector<uint8_t>, OHOS::HDI::Drm::V1_0::MediaKeySessionKeyStatus>& keyStatus, bool hasNewGoodMediaKey) |

- imedia_key_system_callback.h

  | 功能描述                       | 接口名称                                                     |
  | ------------------------------| ----------------------------------------------------------- |
  | MediaKeySystem事件监听回调     | int32_t SendEvent(EventType eventType, int32_t extra, const std::vector<uint8_t>& data) |
 
 - ioem_certificate.h

  | 功能描述                         | 接口名称                                                     |
  | --------------------------------| ------------------------------------------------------------ |
  | 设备证书provision请求            | int32_t GetOemProvisionRequest(std::string& defaultUrl, std::vector<uint8_t>& request) |
  | 设备证书provision请求响应        | int32_t ProvideOemProvisionResponse(const std::vector<uint8_t>& response) |


## 使用方法

在/drivers/peripheral/ClearPlay/test目录下有一个关于ClearPlay的sample，该sample可以验证ClearPlay证书下载、解密播放等基础功能。下面我们就以此sample为例讲述怎样用HDI接口去编写MediaKeySystem的创建、会话管理、证书管理、许可证管理、数据解密等功能的用例。
sample编译命令：./build.sh --product-name rk3568 --build-target clearplay_test_entry
编译产物路径：./out/rk3568/exe.unstripped/hdf/drivers_peripheral_clearplay


1. 在clearplay_sample_media_key_system_factory.cpp的main函数中构造一个media_key_system_factory 对象，该对象中有查询设备所支持插件类型、创建和销毁MediaKeySystem的方法。

   ```
int main(int argc, char *argv[])
{
    // data init
    std::string clearPlayUuid = "com.drm.clearplay";
    bool isSupported = false;

    // create key system factory
    sptr<OHOS::HDI::Drm::V1_0::IMediaKeySystemFactory> media_key_system_factory = new MediaKeySystemFactoryService();

    // IsMediaKeySystemSupported case 1
    media_key_system_factory->IsMediaKeySystemSupported(clearPlayUuid, isoVideoMimeType, SECURE_UNKNOWN, isSupported);
    printf("IsMediaKeySystemSupported: %d, expect 1\n", isSupported);
    // IsMediaKeySystemSupported case 2
    clearPlayUuid = "E79628B6406A6724DCD5A1DA50B53E81"; // wrong uuid
    media_key_system_factory->IsMediaKeySystemSupported(clearPlayUuid, isoVideoMimeType, SECURE_UNKNOWN, isSupported);
    printf("IsMediaKeySystemSupported: %d, expect 0\n", isSupported);

    // CreateMediaKeySystem
    sptr<OHOS::HDI::Drm::V1_0::IMediaKeySystem> media_key_system;
    media_key_system_factory->CreateMediaKeySystem(media_key_system);
    printf("CreateMediaKeySystem\n");

    // MediaKeySystem Close
    media_key_system->Close();
    printf("Close\n");
    return 0;
}   ```

2. clearplay_sample_media_key_system.cpp的main函数中构造一个media_key_system_factory 对象，用该对象创建一个media_key_system对象，使用media_key_system验证设备证书请求、设备证书响应、多会话、属性获取与设置、安全级别获取、DRM度量等功能。

   ```
int main(int argc, char *argv[])
{
    // data init
    std::vector<uint8_t> inputValue;
    std::vector<uint8_t> outputValue;
    std::map<std::string, std::string> metric;
    ContentProtectionLevel level = SECURE_UNKNOWN;
    sptr<OHOS::HDI::Drm::V1_0::IKeySession> key_session_1;
    sptr<OHOS::HDI::Drm::V1_0::IKeySession> key_session_2;
    sptr<OHOS::HDI::Drm::V1_0::IKeySession> key_session_3;
    sptr<OHOS::HDI::Drm::V1_0::IKeySession> key_session_4;

    // create key system factory
    sptr<OHOS::HDI::Drm::V1_0::IMediaKeySystemFactory> media_key_system_factory = new MediaKeySystemFactoryService();

    // CreateMediaKeySystem
    sptr<OHOS::HDI::Drm::V1_0::IMediaKeySystem> media_key_system;
    media_key_system_factory->CreateMediaKeySystem(media_key_system);
    printf("CreateMediaKeySystem\n");

    // set and get configuration
    printf("\ntest set and get configuration\n");
    inputValue.push_back('v');
    inputValue.push_back('a');
    inputValue.push_back('l');
    inputValue.push_back('u');
    inputValue.push_back('e');
    media_key_system->SetConfiguration(CONFIG_TYPE_KEY_SESSION, "name1", inputValue);
    media_key_system->SetConfiguration(CONFIG_TYPE_KEY_SESSION, "name2", inputValue);
    media_key_system->SetConfiguration(CONFIG_TYPE_KEY_SESSION, "name3", inputValue);

    media_key_system->GetConfiguration(CONFIG_TYPE_KEY_SESSION, "name1", outputValue);
    printf("outputValue: %s, expect: value\n", outputValue.data());

    // GetMetric
    printf("\ntest GetMetric\n");
    media_key_system->GetMetric(metric); // 当前可度量信息：插件版本信息、会话数量、解密次数、解密失败次数
    for (auto& pair:metric) {
        printf("key: %s, value: %s\n", pair.first.c_str(), pair.second.c_str());
    }

    // GetContentProtectionLevel
    printf("result of GetContentProtectionLevel: %d, expect: -1\n", media_key_system->GetContentProtectionLevel(level));

    // CreateKeySession
    /*
    SECURE_UNKNOWN = 0,
    SW_SECURE_CRYPTO = 1,
    SW_SECURE_DECODE = 2,
    HW_SECURE_CRYPTO = 3,
    HW_SECURE_DECODE = 4,
    HW_SECURE_ALL = 5,
    */
    printf("\ntest CreateKeySession\n");
    media_key_system->CreateKeySession(SW_SECURE_CRYPTO, key_session_1);
    media_key_system->CreateKeySession(SW_SECURE_DECODE, key_session_2);
    media_key_system->CreateKeySession(HW_SECURE_CRYPTO, key_session_3);
    media_key_system->CreateKeySession(HW_SECURE_DECODE, key_session_4);
    printf("CreateKeySession\n");

    // GetContentProtectionLevel
    printf("\ntest GetContentProtectionLevel\n");
    media_key_system->GetContentProtectionLevel(level);
    printf("level: %d, expect: 4\n", level);
    key_session_4->Close();
    media_key_system->GetContentProtectionLevel(level);
    printf("level: %d, expect: 3\n", level);

    // GenerateKeySystemRequest
    std::vector<uint8_t> request;
    std::string defaultUrl;
    media_key_system->GenerateKeySystemRequest(REQUEST_TYPE_INITIAL, defaultUrl, request);
    // std::string requestString(request.begin(), request.end());
    printf("request: %s, expect: REQUEST_TYPE_INITIAL\n", request.data());

    // ProcessKeySystemResponse
    media_key_system->ProcessKeySystemResponse(REQUEST_TYPE_INITIAL, request);

    // MediaKeySystem Close
    media_key_system->Close();
    printf("Close\n");
    return 0;
}   ```

2. clearplay_sample_media_key_system.cpp的main函数中构造一个media_key_system_factory 对象，用该对象创建一个media_key_system对象，使用media_key_system对象创建key_session对象，使用key_session对象验证许可证获取请求、解析许可证响应、获取解密模块对象以及数据解密和释放解密模块功能。

   ```
int main(int argc, char *argv[])
{
    // create key system factory
    sptr<OHOS::HDI::Drm::V1_0::IMediaKeySystemFactory> media_key_system_factory = new MediaKeySystemFactoryService();

    // CreateMediaKeySystem
    sptr<OHOS::HDI::Drm::V1_0::IMediaKeySystem> media_key_system;
    media_key_system_factory->CreateMediaKeySystem(media_key_system);
    printf("CreateMediaKeySystem\n");

    // CreateKeySession
    printf("\ntest CreateKeySession\n");
    sptr<OHOS::HDI::Drm::V1_0::IKeySession> key_session;
    media_key_system->CreateKeySession(SECURE_UNKNOWN, key_session);
    printf("CreateKeySession\n");

    // ProcessMediaKeyResponse
    printf("\ntest ProcessMediaKeyResponse\n");
    std::string responseString = "key1:1234567812345678";
    std::vector<uint8_t> response(responseString.begin(), responseString.end());
    std::vector<uint8_t> keyId;

    key_session->ProcessMediaKeyResponse(response, keyId);
    printf("keyid: %s, expect: key1\n", keyId.data());

    // GetMediaDecryptModule
    sptr<OHOS::HDI::Drm::V1_0::IMediaDecryptModule> decryptModule;
    key_session->GetMediaDecryptModule(decryptModule);

    // DecryptData
    printf("\nDecryptData\n");
    CryptoInfo info;
    info.type = ALGTYPE_AES_CBC;
    info.keyIdLen = 4;
    info.keyId = keyId;
    info.ivLen = 16;
    info.iv = { // 网络安全，设置默认值，实际调用由DRM框架传真实值
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };
    info.pattern.encryptBlocks = 0;
    info.pattern.skipBlocks = 0;
    SubSample subSample;
    subSample.clearHeaderLen = 0;
    subSample.payLoadLen = 16;
    info.subSamples.push_back(subSample);
    info.subSampleNum = 1;
    std::vector<uint8_t> srcBuffer = { // 网络安全，设置默认值，实际调用由DRM框架传真实值
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };
    std::vector<uint8_t> dstBuffer = { // 网络安全，设置默认值，实际调用由DRM框架传真实值
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };
    decryptModule->DecryptData(false, info, srcBuffer, dstBuffer);
    for (size_t i = 0; i < dstBuffer.size(); ++i) {
        printf("%02x ", dstBuffer[i]);
    }
    printf("\n\n");

    media_key_system->Close();
    printf("Close\n");
    return 0;
}   ```

```
