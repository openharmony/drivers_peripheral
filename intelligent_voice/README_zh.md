# intelligent_voice<a name="ZH-CN_TOPIC_0000001078525242"></a>

-   [简介](#section11660541593)
-   [目录](#section161941989596)
    -   [接口说明](#section1551164914237)
    -   [使用说明](#section129654513264)

-   [相关仓](#section1371113476307)

## 简介<a name="section11660541593"></a>

intelligent_voice仓下主要包含HDI接口，HDI接口主要用于：

-   智能音频引擎的注册、管理、回调
-   Trigger模型的管理、加载、卸载，以及回调

## 目录<a name="section161941989596"></a>

该仓下源代码目录结构如下所示

```
drivers/peripheral/intelligent_voice/
├── hdi_service        # hdi服务,虚拟接口实现
│   └── engine         # engine虚拟接口实现
│   └── trigger        # trigger虚拟接口实现
├── interfaces         # intelligent_voice模块定义的虚拟接口
│   └── include        # 接口定义
```

### 接口说明<a name="section1551164914237"></a>

intelligent_voice模块提供给intelligent_voice_framework可直接调用的能力接口，主要功能有：智能音频引擎的注册、管理、回调,Trigger模型的加载卸载，回调，以及管理等。

提供的部分接口说明如[表1 intelligent_voice HDI接口](#table1513255710559)所示：

**表 1**  intelligent_voice HDI接口

<a name="table1513255710559"></a>
<table><thead align="left"><tr id="row171321857155517"><th class="cellrowborder" valign="top" width="10.721072107210723%" id="mcps1.2.4.1.1"><p id="p6132957115511"><a name="p6132957115511"></a><a name="p6132957115511"></a>头文件</p>
</th>
<th class="cellrowborder" valign="top" width="66.36663666366637%" id="mcps1.2.4.1.2"><p id="p14132125715552"><a name="p14132125715552"></a><a name="p14132125715552"></a>接口名称</p>
</th>
<th class="cellrowborder" valign="top" width="22.912291229122914%" id="mcps1.2.4.1.3"><p id="p18132205755516"><a name="p18132205755516"></a><a name="p18132205755516"></a>功能描述</p>
</th>
</tr>
</thead>
<tbody><tr id="row13132357165514"><td class="cellrowborder" rowspan="13" valign="top" width="10.721072107210723%" headers="mcps1.2.4.1.1 "><p id="p15132185775510"><a name="p15132185775510"></a><a name="p15132185775510"></a>i_engine.h</p>
<p id="p18132157175510"><a name="p18132157175510"></a><a name="p18132157175510"></a></p>
<p id="p2133757135510"><a name="p2133757135510"></a><a name="p2133757135510"></a></p>
</td>
<td class="cellrowborder" valign="top" width="66.36663666366637%" headers="mcps1.2.4.1.2 "><p id="p1213365714550"><a name="p1213365714550"></a><a name="p1213365714550"></a>virtual void OnIntellVoiceEvent(const IntellVoiceEngineCallBackEvent &event) = 0;</p>
</td>
<td class="cellrowborder" valign="top" width="22.912291229122914%" headers="mcps1.2.4.1.3 "><p id="p201331557185512"><a name="p201331557185512"></a><a name="p201331557185512"></a>开启智能语音事件</p>
</td>
</tr>
<tr id="row171331657185514"><td class="cellrowborder" valign="top" headers="mcps1.2.4.1.1 "><p id="p913305715553"><a name="p913305715553"></a><a name="p913305715553"></a>virtual IntellVoiceStatus SetListener(std::shared_ptr<IEngineCallback> listener) = 0;</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.2.4.1.2 "><p id="p161332570553"><a name="p161332570553"></a><a name="p161332570553"></a>设置监听器</p>
</td>
</tr>
<tr id="row41331557165518"><td class="cellrowborder" valign="top" headers="mcps1.2.4.1.1 "><p id="p6133145713559"><a name="p6133145713559"></a><a name="p6133145713559"></a>virtual IntellVoiceStatus Init(const IntellVoiceEngineAdapterInfo &adapterInfo) = 0;</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.2.4.1.2 "><p id="p131331557175510"><a name="p131331557175510"></a><a name="p131331557175510"></a>初始化</p>
</td>
</tr>
<tr id="row77021769584"><td class="cellrowborder" valign="top" headers="mcps1.2.4.1.1 "><p id="p77031566584"><a name="p77031566584"></a><a name="p77031566584"></a>virtual IntellVoiceStatus Release() = 0;</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.2.4.1.2 "><p id="p1470315695811"><a name="p1470315695811"></a><a name="p1470315695811"></a>释放</p>
</td>
</tr>
<tr id="row71857914585"><td class="cellrowborder" valign="top" headers="mcps1.2.4.1.1 "><p id="p1318619155811"><a name="p1318619155811"></a><a name="p1318619155811"></a>virtual IntellVoiceStatus SetParameter(const std::string &keyValueList) = 0;</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.2.4.1.2 "><p id="p1186597589"><a name="p1186597589"></a><a name="p1186597589"></a>设置参数</p>
</td>
</tr>
<tr id="row18831119115815"><td class="cellrowborder" valign="top" headers="mcps1.2.4.1.1 "><p id="p48323975814"><a name="p48323975814"></a><a name="p48323975814"></a>virtual IntellVoiceStatus GetParameter(const std::string &keyList, getParameterCb cb) = 0;</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.2.4.1.2 "><p id="p15832129135813"><a name="p15832129135813"></a><a name="p15832129135813"></a>获取参数</p>
</td>
</tr>
<tr id="row71857914585"><td class="cellrowborder" valign="top" headers="mcps1.2.4.1.1 "><p id="p1318619155811"><a name="p1318619155811"></a><a name="p1318619155811"></a>virtual IntellVoiceStatus Write(const uint8_t *buffer, uint32_t size) = 0;</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.2.4.1.2 "><p id="p1186597589"><a name="p1186597589"></a><a name="p1186597589"></a>写入</p>
</td>
</tr>
<tr id="row18831119115815"><td class="cellrowborder" valign="top" headers="mcps1.2.4.1.1 "><p id="p48323975814"><a name="p48323975814"></a><a name="p48323975814"></a>virtual IntellVoiceStatus Start(const StartInfo& info) = 0;</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.2.4.1.2 "><p id="p15832129135813"><a name="p15832129135813"></a><a name="p15832129135813"></a>启动</p>
</td>
</tr>
<tr id="row71857914585"><td class="cellrowborder" valign="top" headers="mcps1.2.4.1.1 "><p id="p1318619155811"><a name="p1318619155811"></a><a name="p1318619155811"></a>virtual IntellVoiceStatus Stop() = 0;</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.2.4.1.2 "><p id="p1186597589"><a name="p1186597589"></a><a name="p1186597589"></a>停止</p>
</td>
</tr>
<tr id="row18831119115815"><td class="cellrowborder" valign="top" headers="mcps1.2.4.1.1 "><p id="p48323975814"><a name="p48323975814"></a><a name="p48323975814"></a>virtual IntellVoiceStatus Cancel() = 0;</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.2.4.1.2 "><p id="p15832129135813"><a name="p15832129135813"></a><a name="p15832129135813"></a>取消</p>
</td>
</tr>
<tr id="row18831119115815"><td class="cellrowborder" valign="top" headers="mcps1.2.4.1.1 "><p id="p48323975814"><a name="p48323975814"></a><a name="p48323975814"></a>virtual IntellVoiceStatus ReadFileData(const std::string &filePath, getFileDataCb cb) = 0;</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.2.4.1.2 "><p id="p15832129135813"><a name="p15832129135813"></a><a name="p15832129135813"></a>读取文件数据</p>
</td>
</tr>
<tr id="row18831119115815"><td class="cellrowborder" valign="top" headers="mcps1.2.4.1.1 "><p id="p48323975814"><a name="p48323975814"></a><a name="p48323975814"></a>virtual int32_t CreateAdapter(const IntellVoiceEngineAdapterDescriptor &descriptor, std::unique_ptr<IEngine> &engine) = 0;</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.2.4.1.2 "><p id="p15832129135813"><a name="p15832129135813"></a><a name="p15832129135813"></a>创建适配器</p>
</td>
</tr>
<tr id="row18831119115815"><td class="cellrowborder" valign="top" headers="mcps1.2.4.1.1 "><p id="p48323975814"><a name="p48323975814"></a><a name="p48323975814"></a>virtual int32_t ReleaseAdapter(const IntellVoiceEngineAdapterDescriptor &descriptor) = 0;</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.2.4.1.2 "><p id="p15832129135813"><a name="p15832129135813"></a><a name="p15832129135813"></a>释放适配器</p>
</td>
</tr>
<tr id="row1267017500274"><td class="cellrowborder" rowspan="8" align="left" valign="top" width="12.821282128212822%" headers="mcps1.2.4.1.1 "><p id="p15674038913"><a name="p15674038913"></a><a name="p15674038913"></a></p>
<p id="p825185015460"><a name="p825185015460"></a><a name="p825185015460"></a>i_trigger.h</p>
<p id="p2133757135510"><a name="p2133757135510"></a><a name="p2133757135510"></a></p>
<p id="p14171441118"><a name="p14171441118"></a><a name="p14171441118"></a></p>
<p id="p57063567463"><a name="p57063567463"></a><a name="p57063567463"></a></p>
<p id="p1285144710118"><a name="p1285144710118"></a><a name="p1285144710118"></a></p>
</td>
<td class="cellrowborder" valign="top" width="62.16621662166217%" headers="mcps1.2.4.1.2 "><p id="p6264341172811"><a name="p6264341172811"></a><a name="p6264341172811"></a>virtual void OnRecognitionHdiEvent(const IntellVoiceRecognitionEvent &event, int32_t cookie) = 0;</p>
</td>
<td class="cellrowborder" valign="top" width="25.012501250125013%" headers="mcps1.2.4.1.3 "><p id="p13264114182817"><a name="p13264114182817"></a><a name="p13264114182817"></a>开启识别接口事件</p>
</td>
</tr>
<tr id="row2661171172814"><td class="cellrowborder" valign="top" headers="mcps1.2.4.1.1 "><p id="p126514172811"><a name="p126514172811"></a><a name="p126514172811"></a>virtual int32_t GetProperties(IntellVoiceTriggerProperties &properties) = 0;</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.2.4.1.2 "><p id="p15265164122819"><a name="p15265164122819"></a><a name="p15265164122819"></a>获取属性</p>
</td>
</tr>
<tr id="row4385112822818"><td class="cellrowborder" valign="top" headers="mcps1.2.4.1.1 "><p id="p10265134111284"><a name="p10265134111284"></a><a name="p10265134111284"></a>virtual int32_t LoadIntellVoiceTriggerModel(const TriggerModel &model,
        const std::shared_ptr<ITriggerCallback> &callback, int32_t cookie, int32_t &handle) = 0;</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.2.4.1.2 "><p id="p726554110289"><a name="p726554110289"></a><a name="p726554110289"></a>加载智能语音触发模型</p>
</td>
</tr>
<tr id="row181371630162816"><td class="cellrowborder" valign="top" headers="mcps1.2.4.1.1 "><p id="p426517411284"><a name="p426517411284"></a><a name="p426517411284"></a>virtual int32_t UnloadIntellVoiceTriggerModel(int32_t handle) = 0;</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.2.4.1.2 "><p id="p1926512413287"><a name="p1926512413287"></a><a name="p1926512413287"></a>卸载智能语音触发模型</p>
</td>
</tr>
<tr id="row01531026142811"><td class="cellrowborder" valign="top" headers="mcps1.2.4.1.1 "><p id="p182651741162812"><a name="p182651741162812"></a><a name="p182651741162812"></a>virtual int32_t Start(int32_t handle) = 0;</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.2.4.1.2 "><p id="p142651241152813"><a name="p142651241152813"></a><a name="p142651241152813"></a>启动</p>
</td>
</tr>
<tr id="row11460182372815"><td class="cellrowborder" valign="top" headers="mcps1.2.4.1.1 "><p id="p1626534118284"><a name="p1626534118284"></a><a name="p1626534118284"></a>virtual int32_t Stop(int32_t handle) = 0;</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.2.4.1.2 "><p id="p72661241112817"><a name="p72661241112817"></a><a name="p72661241112817"></a>停止</p>
</td>
</tr>
<tr id="row11460182372815"><td class="cellrowborder" valign="top" headers="mcps1.2.4.1.1 "><p id="p1626534118284"><a name="p1626534118284"></a><a name="p1626534118284"></a>virtual int32_t LoadAdapter(const IntellVoiceTriggerAdapterDsecriptor &descriptor, std::unique_ptr<ITrigger> &adapter) = 0;</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.2.4.1.2 "><p id="p72661241112817"><a name="p72661241112817"></a><a name="p72661241112817"></a>加载适配器</p>
</td>
</tr>
<tr id="row11460182372815"><td class="cellrowborder" valign="top" headers="mcps1.2.4.1.1 "><p id="p1626534118284"><a name="p1626534118284"></a><a name="p1626534118284"></a>virtual int32_t UnloadAdapter(const IntellVoiceTriggerAdapterDsecriptor &descriptor) = 0;</p>
</td>
<td class="cellrowborder" valign="top" headers="mcps1.2.4.1.2 "><p id="p72661241112817"><a name="p72661241112817"></a><a name="p72661241112817"></a>卸载适配器</p>
</td>
</tr>
</tbody>
</table>

### 使用说明<a name="section129654513264"></a>

该仓核心功能包括两个方面：

1.  提供intelligent_voice HDI接口供framework层调用，实现智能音频服务的基本功能。
2.  作为标准南向接口，保证南向OEM产商实现HDI-adapter的规范性，保证生态良性演进。

具体接口调用及实现，以接口注释为准。

## 相关仓<a name="section1371113476307"></a>

[驱动子系统](https://gitee.com/openharmony/docs/blob/master/zh-cn/readme/%E9%A9%B1%E5%8A%A8%E5%AD%90%E7%B3%BB%E7%BB%9F.md)

[drivers\_framework](https://gitee.com/openharmony/drivers_framework/blob/master/README_zh.md)

[drivers\_adapter](https://gitee.com/openharmony/drivers_adapter/blob/master/README_zh.md)

[drivers\_adapter\_khdf\_linux](https://gitee.com/openharmony/drivers_adapter_khdf_linux/blob/master/README_zh.md)

[drivers\_peripheral](https://gitee.com/openharmony/drivers_peripheral)

