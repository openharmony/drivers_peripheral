- [HDF Audio系统测试用例使用指南](#hdf-audio系统测试用例使用指南)
  - [1. 简介](#1-简介)
    - [1.1 目录结构](#11-目录结构)
    - [1.2 特殊用例说明](#12-特殊用例说明)
      - [1.2.1 硬件耦合相关测试用例](#121-硬件耦合相关测试用例)
        - [1.2.1.1 UHDF层非通用（硬件耦合）测试用例](#1211-uhdf层非通用硬件耦合测试用例)
        - [1.2.1.2 LIB层非通用（硬件耦合）测试用例](#1212-lib层非通用硬件耦合测试用例)
      - [1.2.2 ALSA模式测试用例](#122-alsa模式测试用例)
      - [1.2.3 录音阈值上报测试用例](#123-录音阈值上报测试用例)
  - [2. 适用版本](#2-适用版本)
  - [3. 适用平台（已适配的SOC）](#3-适用平台已适配的soc)
  - [4. 使用方法](#4-使用方法)
    - [4.1 用例编译](#41-用例编译)
    - [4.2 测试套及资源文件推送](#42-测试套及资源文件推送)
    - [4.3 测试用例执行（手动执行）](#43-测试用例执行手动执行)

## HDF Audio系统测试用例使用指南
### 1. 简介

本使用指南主要说明音频驱动模型对外接口测试用例，并根据测试内容划分不同目录。包含以下内容：

- ADM对外接口测试用例
- UHDF层接口测试用例
- LIB层接口测试用例
- 功能测试用例

#### 1.1 目录结构


测试用例路径：drivers/peripheral/audio/test/systemtest

目录结构如下：

```bash
|-- common          #测试用例公共函数
|   |-- adm_common                 #ADM层测试用例公共函数
|   |-- hdi_common                 #UHDF层测试用例公共函数
|   |-- hdi_service_common         #IDL UHDF层测试用例公共函数
|   |-- lib_common                 #LIB层测试用例公共函数
|-- audio_adapter   #声卡测试用例
|   |-- audio_usb                  #USB声卡测试用例
|-- audio_function  #功能测试用例
|   |-- audio_loadadapter_report   #加载声卡成功上报测试用例
|   |-- audio_multi_mic_spk        #多mic、多speaker测试用例
|   |-- audio_pathroute            #通路选择测试用例
|   |-- audio_server               #hdi接口功能测试用例（播放、录音）
|   |-- audio_smartpa              #外置声卡测试用例
|   |-- audio_threshold_report     #阈值上报测试用例
|-- adm             #ADM层接口测试用例
|   |-- audio_adm_interface        #adm对外接口测试用例
|-- hdi             #UHDF层接口测试用例
|   |-- common                     #hdi接口通用测试用例 
|   |   |-- adapter
|   |   |-- capture
|   |   |-- manager
|   |   |-- render
|   |-- hardwaredependence         #hdi接口非通用测试用例(硬件耦合)
|   |   |-- capture
|   |   |-- render
|   |-- hdiperformace              #hdi接口时延测试用例
|   |-- hdireliability             #hdi接口可靠性测试用例
|-- hdi_service     #UHDF层idl化接口测试用例
|   |-- common                     #idl化hdi接口通用测试用例 
|   |   |-- adapter
|   |   |-- capture
|   |   |-- manager
|   |   |-- render
|   |-- hardwaredependence         #idl化hdi接口非通用测试用例(硬件耦合)
|   |   |-- capture
|   |   |-- render
|   |-- hdiperformace              #idl化hdi接口时延测试用例
|-- supportlibs     #LIB层接口测试用例（包含adm lib和alsa lib接口测试用例）
        |-- common                 #lib接口通用测试用例
        |   |-- capture
        |   |-- render
        |-- hardwaredependence     #lib接口非通用测试用例(硬件耦合)
            |-- capture
            |-- render
```

#### 1.2 特殊用例说明
##### 1.2.1 硬件耦合相关测试用例
由于音频驱动模型对外接口的部分接口参数与硬件能力有耦合，此类用例与硬件耦合，导致无法作为通用用例。在移植过程中及门禁用例提取过程中，需要特别关注。

###### 1.2.1.1 UHDF层非通用（硬件耦合）测试用例
UHDF层存在硬件耦合接口，如：SetSampleAttributes、SetChannelMode等。
1. SetSampleAttributes接口测试用例中设置参数时会设置不同的“位宽、采样率、声道数”等与硬件相关的参数。
2. SetChannelMode 接口测试用例中设置声道模式时会设置不同的模式，声道模式的支持与硬件相关。

硬件不支持，接口会返回失败；硬件支持，接口返回成功。因此不同的开发板会出现不同的结果，在移植测试用例的过程中需要根据硬件的情况进行适配。

<table width="100%" border="0">
<caption>非通用测试用例接口列表</caption>
    <tr>
        <th width="20%" align="center">所属类</th>
        <th align="center" width="30%">接口名</th>
        <th width="50%" align="center">说明</th>
    </tr>
    <tr>
        <td width="20%" rowspan ="7">capture</td>
        <td width="30%">SetSampleAttributes</td>
        <td width="50%">遍历设置不同的硬件参数</td>
    </tr>
    <tr>
        <td>GetSampleAttributes</td>
        <td>获取设置的硬件参数</td>
    </tr>
    <tr>
        <td>GetFrameSize</td>
        <td>与SetSampleAttributes组合测试</td>
    </tr>
    <tr>
        <td>GetFrameCount</td>
        <td>与SetSampleAttributes组合测试</td>
    </tr>
    <tr>
        <td>GetMmapPosition</td>
        <td>与SetSampleAttributes组合测试</td>
    </tr>
    <tr>
        <td>GetCurrentChannelId</td>
        <td>与SetSampleAttributes组合测试</td>
    </tr>
    <tr>
        <td>GetCapturePosition</td>
        <td>与SetSampleAttributes组合测试</td>
    </tr>
    <tr>
        <td width="20%" rowspan ="9">render</td>
        <td width="30%">SetSampleAttributes</td>
        <td width="50%">遍历设置不同的硬件参数</td>
    </tr>
    <tr>
        <td>GetSampleAttributes</td>
        <td>获取设置的硬件参数</td>
    </tr>
    <tr>
        <td>SetChannelMode</td>
        <td>遍历设置不同的声道模式</td>
    </tr>
    <tr>
        <td>GetChannelMode</td>
        <td>获取设置的声道模式</td>
    </tr>
    <tr>
        <td>GetFrameSize</td>
        <td>与SetSampleAttributes组合测试</td>
    </tr>
    <tr>
        <td>GetFrameCount</td>
        <td>与SetSampleAttributes组合测试</td>
    </tr>
    <tr>
        <td>GetMmapPosition</td>
        <td>与SetSampleAttributes组合测试</td>
    </tr>
    <tr>
        <td>GetCurrentChannelId</td>
        <td>与SetSampleAttributes组合测试</td>
    </tr>
    <tr>
        <td>GetRenderPosition</td>
        <td>与SetSampleAttributes组合测试</td>
    </tr>
<table>

###### 1.2.1.2 LIB层非通用（硬件耦合）测试用例
LIB层存在硬件耦合接口：为音量，增益，场景切换相关接口。
1. 调用lib接口获取硬件的音量范围、增益范围，并校验。
2. 调用lib接口设置不同的音量或增益，超出范围便会失败。
3. 调用lib接口设置不同的通路进行场景切换。

以上接口调用返回结果均与硬件相关，不同硬件默认的范围、通路不同，测试用例需根据硬件适配。
<table width="100%" border="0">
<caption>非通用测试用例接口列表</caption>
    <tr>
        <th width="20%" align="center">所属类</th>
        <th align="center" width="50%">命令码</th>
        <th width="30%" align="center">说明</th>
    </tr>
    <tr>
        <td width="20%" rowspan ="7">capture</td>
        <td width="50%"> AUDIODRV_CTL_IOCTL_GAINTHRESHOLD_CAPTURE</td>
        <td width="30%">获取增益阈值</td>
    </tr>
    <tr>
        <td>AUDIODRV_CTL_IOCTL_GAIN_WRITE_CAPTURE</td>
        <td>设置增益</td>
    </tr>
    <tr>
        <td>AUDIODRV_CTL_IOCTL_GAIN_READ_CAPTURE</td>
        <td>获取增益</td>
    </tr>
    <tr>
        <td>AUDIODRV_CTL_IOCTL_SCENESELECT_CAPTURE</td>
        <td>场景切换</td>
    </tr>
    <tr>
        <td>AUDIODRV_CTL_IOCTL_VOL_THRESHOLD_CAPTURE</td>
        <td>获取音量阈值</td>
    </tr>
    <tr>
        <td>AUDIODRV_CTL_IOCTL_ELEM_WRITE_CAPTURE</td>
        <td>设置音量</td>
    </tr>
    <tr>
        <td>AUDIODRV_CTL_IOCTL_ELEM_READ_CAPTURE</td>
        <td>获取音量</td>
    </tr>
    <tr>
        <td width="20%" rowspan ="7">render</td>
        <td width="50%">AUDIODRV_CTL_IOCTL_GAINTHRESHOLD</td>
        <td width="30%">获取增益阈值</td>
    </tr>
    <tr>
        <td>AUDIODRV_CTL_IOCTL_GAIN_WRITE</td>
        <td>设置增益</td>
    </tr>
    <tr>
        <td>AUDIODRV_CTL_IOCTL_GAIN_WRITE</td>
        <td>获取增益</td>
    </tr>
    <tr>
        <td>AUDIODRV_CTL_IOCTL_SCENESELECT</td>
        <td>场景切换</td>
    </tr>
    <tr>
        <td>AUDIODRV_CTL_IOCTL_VOL_THRESHOLD</td>
        <td>获取音量阈值</td>
    </tr>
    <tr>
        <td>AUDIODRV_CTL_IOCTL_ELEM_WRITE</td>
        <td>设置音量</td>
    </tr>
    <tr>
        <td>AUDIODRV_CTL_IOCTL_ELEM_READ</td>
        <td>获取音量</td>
    </tr>
<table>

##### 1.2.2 ALSA模式测试用例
音频驱动模型为支持南向生态厂商快速接入鸿蒙、支持快速产品化而提供的“ALSA兼容方案”，采用插件化的适配器模式通过alsa-lib对接ALSA。当采用“ALSA兼容方案”时，需编译ALSA模式测试用例。测试用例分为两部分：

1.	LIB层接口测试用例
</br>ALSA模式LIB层测试用例为alsa-lib接口测试用例，存放在supportlis/common目录下，与adm_interface_lib测试用例同一目录下的不同测试套文件，在编译文件内配置选择编译目标。
  ````bash 
  ohos_systemtest("hdf_audio_lib_capture_test") {
    module_out_path = module_output_path
    sources = [
      "../../../common/hdi_common/src/audio_hdi_common.cpp",
      "../../../common/lib_common/src/audio_lib_common.cpp",
    ]
    #drivers_peripheral_audio_alsa_lib
    if(defined(drivers_peripheral_audio_alsa_lib) && drivers_peripheral_audio_alsa_lib == true) {
      sources += ["src/audio_alsa_libcapture_test.cpp"]
    }else {
      sources += ["src/audio_libcapture_test.cpp"]
    }
  ````
2.	UHDF层接口测试用例
</br>ALSA模式UHDF层测试用例与ADM模式共用一套测试用例，ALSA模式部分hdi接口未适配，在测试代码中使用宏区分。
<table width="100%" border="0">
<caption>ALSA未适配hdi接口列表</caption>
    <thead>
    <tr>
        <th width="20%" align="center">所属类</th>
        <th width="40%" align="center">接口</th>
        <th width="40%" align="center">说明</th>
    </tr>
    </thead>
    <tbody>
    <tr>
        <td width="20%" rowspan ="6">capture</td>
        <td width="40%">Flush</td>
        <td width="40%">刷新</td>
    </tr>
    <tr>
        <td>CheckSceneCapability</td>
        <td>查询场景支持能力</td>
    </tr>
    <tr>
        <td>SelectScene</td>
        <td>选择场景</td>
    </tr>
    <tr>
        <td>GetGainThreshold</td>
        <td>获取增益阈值</td>
    </tr>
    <tr>
        <td>GetGain</td>
        <td>获取增益</td>
    </tr>
    <tr>
        <td>SetGain</td>
        <td>设置增益</td>
    </tr>
    <tr>
        <td width="20%" rowspan ="8">render</td>
        <td width="40%">SetRenderSpeed</td>
        <td width="40%">设置播放速度</td>
    </tr>
    <tr>
        <td>GetRenderSpeed</td>
        <td>获取播放速度</td>
    </tr>
    <tr>
        <td>SetChannelMode</td>
        <td>设置声道模式</td>
    </tr>
    <tr>
        <td>GetChannelMode</td>
        <td>获取声道模式</td>
    </tr>
    <tr>
        <td>Flush</td>
        <td>刷新</td>
    </tr>
    <tr>
        <td>GetGainThreshold</td>
        <td>获取增益阈值</td>
    </tr>
    <tr>
        <td>GetGain</td>
        <td>获取增益</td>
    </tr>
    <tr>
        <td>SetGain</td>
        <td>设置增益</td>
    </tr>
    </tbody>
<table>

  ````bash 
    #gn内添加编译宏ALSA_LIB_MODE用于区分测试用例
    if(defined(drivers_peripheral_audio_alsa_lib) && drivers_peripheral_audio_alsa_lib == true) {
      defines += [ "ALSA_LIB_MODE" ]
    }
    #测试用例代码内使用示例
    ret = render->attr.SetSampleAttributes(render, &attrs2);
#ifdef ALSA_LIB_MODE
    EXPECT_EQ(AUDIO_HAL_SUCCESS, ret);
#else
    EXPECT_EQ(AUDIO_HAL_ERR_INTERNAL, ret);
#endif
  ````
<b>注：编译ALSA测试用例是需要设置ALSA编译选项，由drivers_peripheral_audio_alsa_lib编译选项控制，当"drivers_peripheral_audio_alsa_lib = true"表示编译ALSA模式测试用例，编译配置文件路径为./drivers/peripheral/audio/audio.gni文件内。</b>
##### 1.2.3 录音阈值上报测试用例

  码云上音频驱动模型默认不编译录音阈值上报功能代码，因此该功能对应的测试套（hdf_audio_threshold_report_test）默认不编译，如需编译需要手动修改gn文件，去掉“#”字符注释。gn文件路径为./audio_function/BUILD.gn
```bash
group("function") {
  if (!defined(ohos_lite)) {
    testonly = true
  }
  deps = [ "audio_server:hdf_audio_hdi_server_function_test" ]
  if (defined(ohos_lite)) {
    deps += [
      "audio_pathroute:hdf_audio_hdi_path_route_test",
      "audio_smartpa:hdf_audio_smartpa_test",
    ]
  } else {
    #deps += [ "audio_threshold_report:hdf_audio_threshold_report_test" ] #录音阈值上报测试套
  ....
```
### 2. 适用版本
当前测试用例适用码云mater主仓音频驱动模型版本。

### 3. 适用平台（已适配的SOC）
  目前已适配开发板如下：
1.	rk3568
2.	Hi3516DV300

### 4. 使用方法
#### 4.1 用例编译
注：以下目录均以Openharmony代码根目录为根目录

1.	测试用例模式修改
</br>音频驱动模型UHDF层支持binder模式和passthrough模式，因此针对不同的模式需要编译对应的测试用例，测试用的模式通过修改编译选项控制，编译配置文件路径为<b>“/drivers/peripheral/audio/audio.gni”</b>。编译选项为<b>“true”</b>表示编译；为<b>“false”</b>表示不编译，两种模式测试用例一次只能编译其中一种。

<table width="100%" border="0">
<caption></caption>
    <tr>
        <th width="25%" align="center">编译选项</th>
        <th width="25%" align="center">含义</th>
        <th width="25%" align="center">值</th>
        <th width="25%" align="center">备注</th>
    </tr>
    <tr>
        <td width="25%">enable_audio_adm_so</td>
        <td width="25%">passthrough模式</td>
        <td width="25%">true/false</td>
        <td width="25%">默认不编译(false)</td>
    </tr>
    <tr>
        <td>enable_audio_adm_service</td>
        <td>binder模式</td>
        <td>true/false</td>
        <td>默认编译(true)</td>
    </tr>
</table>

2.  测试用例编译命令
在根目录下输入命令：
  ```bash 
  ./build.sh --product-name  XXX  --build-target drivers/peripheral/audio/test/systemtest
  ```
“XXX”为产品名，如编译rk3568开发板测试用例,输入如下命令：
```bash
./build.sh --product-name rk3568 --build-target drivers/peripheral/audio/test/systemtest
```
3. 测试用例输出目录

以rk3568为例，输出目录为：
```bash
./out/rk3568/tests/systemtest/drivers_peripheral_audio/audio
```
#### 4.2 测试套及资源文件推送（手动执行）
1. 测试用例执行依赖文件推送

Render相关测试用例执行需要推送audiorendertest.wav和lowlatencyrendertest.wav两个音频文件，音频文件路径为drivers/peripheral/audio/test/resource/。推动至开发板”/data/test”目录下,具体哪些用例需要推送音频文件可查看drivers/peripheral/audio/test/resource/ohos_test.xml，在cmd窗口输入命令:
```bash
hdc shll mkdir /data/test
hdc file send XXX[本地路径]/audiorendertest.wav  /data/test
hdc file send XXX[本地路径]/lowlatencyrendertest.wav  /data/test
```

2. 测试用例推送

测试用例使用hdc推送至开发板，在cmd窗口输入命令：
```bash
hdc file send XXX[本地路径]/hdf_audio_hdi_manager_test  /data/test
```

#### 4.3 测试用例执行（手动执行）

1. 进入单板
通过hdc进入开发板，在cmd窗口输入命令
 ```bash
  hdc shell
 ```

2. 修改测试用例权限及执行
进入/data/test目录，输入命令
```bash
cd /data/test                 #进入data目录
chmod  +x “测试套名称"   #更改测试套权限
./测试套                 #执行测试套
```
测试用例执行示例
````bash
# chmod +x hdf_audio_hdi_manager_test
# ./hdf_audio_hdi_manager_test
Running main() from gmock_main.cc
[==========] Running 4 tests from 1 test case.
[----------] Global test environment set-up.
[----------] 4 tests from AudioHdiManagerTest
[ RUN      ] AudioHdiManagerTest.SUB_Audio_HDI_ReleaseAudioManagerObject_0001
[       OK ] AudioHdiManagerTest.SUB_Audio_HDI_ReleaseAudioManagerObject_0001 (1 ms)
[ RUN      ] AudioHdiManagerTest.SUB_Audio_HDI_ReleaseAudioManagerObject_0002
[       OK ] AudioHdiManagerTest.SUB_Audio_HDI_ReleaseAudioManagerObject_0002 (0 ms)
[ RUN      ] AudioHdiManagerTest.SUB_Audio_HDI_ReleaseAudioManagerObject_0003
[       OK ] AudioHdiManagerTest.SUB_Audio_HDI_ReleaseAudioManagerObject_0003 (0 ms)
[ RUN      ] AudioHdiManagerTest.SUB_Audio_HDI_ReleaseAudioManagerObject_0004
[       OK ] AudioHdiManagerTest.SUB_Audio_HDI_ReleaseAudioManagerObject_0004 (1 ms)
[----------] 4 tests from AudioHdiManagerTest (2 ms total)

[----------] Global test environment tear-down
Gtest xml output finished
[==========] 4 tests from 1 test case ran. (4 ms total)
[  PASSED  ] 4 tests.
````