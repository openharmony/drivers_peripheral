# 星闪组件<a name="ZH-CN_TOPIC_0000001148577119"></a>

-   [简介](#section11660541593)
-   [目录](#section161941989596)
-   [约束](#section119744591305)
-   [说明](#section1312121216216)
    -   [DLI接口使用说明](#section129654513264)

-   [相关仓](#section1371113476307)

## 简介<a name="section11660541593"></a>

星闪（NearLink）驱动组件为设备提供接入与使用星闪短距通信协议的相关接口，包括DLI初始化，数据收发以及关闭星闪DLI等。

## 目录<a name="section161941989596"></a>

```
/foundation/drivers/peripheral/nearlink
├── bundle.json                              # 组件描述及依赖配置
├── drivers_peripheral_nearlink.gni         # 编译特性参数配置
├── dli                                     # DLI模块
│   └── test                                # DLI测试用例
└── LICENSE                                  # 版权声明文件
└── bundle.json                              # 部件描述文件
```

## 约束<a name="section119744591305"></a>

星闪驱动组件使用C++语言编写，基于DLI框架，仅支持标准系统。

## 说明<a name="section1312121216216"></a>

目前提供星闪DLI接口，DLI接口包括初始化、发送接收DLI数据包、关闭等功能。


### DLI接口使用说明<a name="section129654513264"></a>

-   初始化星闪HAL：

```
/* 初始化星闪HAL，注册回调 */
int32_t SleHalInit(const sptr<ISleHciCallback>& callbackObj);
```

-   发送数据包：

```
/* 向芯片发送数据包 */
int32_t SleSendHciPacket(const std::vector<uint8_t>& data);
```

-   接收数据包：

```
/* 接收来自芯片的数据包 */
int32_t hciPacketReceived(uint32_t type, const std::vector<uint8_t> &data);
```


-   关闭星闪DLI：

```
/* 关闭星闪DLI，释放资源 */
int32_t Close();
```

## 相关仓<a name="section1371113476307"></a>

drivers\_peripheral\_nearlink
