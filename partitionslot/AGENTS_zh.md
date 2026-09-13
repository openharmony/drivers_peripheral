# AGENTS.md — drivers/peripheral/partitionslot

面向在 OpenHarmony **drivers_peripheral_partitionslot** 部件（PartitionSlot HDI
服务实现——A/B 多槽位启动分区管理）工作的编码 Agent 的指南。在修改
`drivers/peripheral/partitionslot/` 下任何文件之前，请先阅读本文档。

> 作用范围：部件根目录（`drivers/peripheral/partitionslot`），位于
> `drivers/peripheral` git 仓库内。HDI 接口（IDL、生成的 proxy/stub）在独立
> 仓库：`drivers/interface/partitionslot`。

## 1. 代码结构

### 1.1 本部件负责的内容

PartitionSlot HDI 服务的实现侧，共四个 API：
- `GetCurrentSlot`——查询单板当前从哪个分区槽位启动、共支持几个槽位；
- `GetSlotSuffix`——槽位序号 → 分区名后缀（`"_a"` / `"_b"`）；
- `SetActiveSlot`——切换设备下次启动使用的槽位；
- `SetSlotUnbootable`——将某槽位置为不可启动。

槽位状态直接持久化在 bootctrl 分区（`/dev/block/by-name/bootctrl`）；槽位数量
来自系统参数 `ohos.boot.bootslots`（默认 1）。典型消费方：`base/startup/init`
的 `begetctl partitionslot` 工具（`services/begetctl/partitionslot.cpp`，子命令
`getslot` / `getsuffix` / `setactive` / `setunboot`；其中 `setactive` 在启动仓
AGENTS.md 中被列为破坏性命令）。

### 1.2 运行时调用链（依赖方向：上层调用下层；严禁反向）

```
调用方（如 startup_init 的 begetctl partitionslot）
  → libpartitionslot_proxy_1.0        生成的 proxy（drivers/interface 仓库）
  → HDF dispatch in partitionslot_host  HdfSBuf ↔ MessageParcel 转换后转发给 stub
  → PartitionSlotImpl                  实现 IPartitionSlot（libpartition_slot_service_1.0）
  → PartitionSlotManager               DelayedSingleton，全部实际逻辑（libpartition_slot_manager）
  → /dev/block/by-name/bootctrl        裸 open/lseek/read/write
```

| 路径 | 产物 | 职责 |
| --- | --- | --- |
| `hal/src/partitionslot_manager.cpp` | `libpartition_slot_manager`（inner_kit；装 system + updater 镜像） | bootctrl 读写、系统参数读取 |
| `hdi_service/src/partitionslot_impl.cpp` | `libpartition_slot_service_1.0`（装 chipset 镜像） | IDL 方法实现；导出 `extern "C" PartitionSlotImplGetInstance` 供 HDI 框架 dlsym |
| `hdi_service/src/partition_slot_driver.cpp` | `libpartitionslot_driver`（`shlib_type=hdi`；装 chipset 镜像） | `HdfDriverEntry`（moduleName `partitionslot_interface_service`）；Bind 经 `ObjectCollector` 接线 stub |
| `test/unittest/hdf_partitionslot_test.cpp` | `partitionslot_hdi_test` | 真机 gtest（HWTEST_F），每个 API 一个用例 |
| `BUILD.gn` / `bundle.json` | — | 顶层 group `partitionslot_entry`；inner_kits 声明 |

部署形态由产品侧 HDF 配置决定（`vendor/<厂商>/<产品>/hdf_config/uhdf/device_info.hcs`
的 `partitionslot` 段）：宿主 `partitionslot_host`、服务名
`partition_slot_service`、驱动 `libpartitionslot_driver.z.so`、`preload = 2`
（按需加载——`IPartitionSlot::Get(true)` 触发拉起）。宿主进程的 uid/gid 也来自
该配置（rk3568：uid `useriam`、gid `["useriam", "update"]`）——排查 bootctrl
权限问题时先查这里。

高风险 / 频繁变更路径（此处改动需格外谨慎）：
`hal/src/partitionslot_manager.cpp`（`MISC_PARTITION_*` 磁盘布局常量、槽位编号）、
`bundle.json`（`inner_kits` 是对下游暴露的面）。

嵌套指导文件：本部件内无。接口侧有独立的
`drivers/interface/partitionslot/AGENTS.md`（中文镜像 `AGENTS_zh.md`）。

## 2. 知识路由——编辑前先读

在修改任何文件之前，先向自己说明：(1) 任务类别；(2) 已加载 §2.1 中的哪一行
（凡涉及 API 语义，还需加上 IDL 那一行）；(3) 适用 §3 的哪条约束。三者答不全，
先停下阅读。

### 2.1 按任务路由

| 任务 | 先读 | 需加载的关键概念 |
| --- | --- | --- |
| bootctrl 读写、系统参数 | `hal/src/partitionslot_manager.cpp` | active slot @ 偏移 1024（4 字节）、unbootable @ 1028（4 字节）；`ohos.boot.bootslots` |
| HDI 方法行为、服务加载 | `hdi_service/src/partitionslot_impl.cpp` | `PartitionSlotImplGetInstance` 是 dlsym 入口；`IPartitionSlot::Get(true)` 加载服务 |
| 驱动注册、Dispatch、stub 接线 | `hdi_service/src/partition_slot_driver.cpp` | `HdfDriverEntry` 的 Bind/Init/Release；`SbufToParcel`；`ObjectCollector::GetOrNewObject` |
| 测试用例 / 预期 | `test/unittest/hdf_partitionslot_test.cpp` | `IDeviceManager::LoadDevice("partition_slot_service")`；用例 003 会切换 active slot 再恢复；用例 004 将槽位 2 置为不可启动且**不恢复** |
| API 语义、参数方向、签名 | `drivers/interface/partitionslot/v1_0/IPartitionSlot.idl` 及其 `AGENTS.md` | 返回值契约；版本规则 |
| 宿主 / 服务名 / 加载策略 | `vendor/<厂商>/<产品>/hdf_config/uhdf/device_info.hcs`（`partitionslot` 段） | `preload = 2` 按需加载 |

### 2.2 按术语路由（任务/日志/issue/API 中出现下列术语时）

| 术语 / 缩写 | 概念 |
| --- | --- |
| slot、A/B 分区、active slot、unbootable、slot suffix（槽位后缀） | 各方法的定义见 `IPartitionSlot.idl`；编号怪癖见 §3.1.3 |
| bootctrl | 保存槽位状态的 misc 类分区；布局常量在 `hal/src/partitionslot_manager.cpp` |
| `bootslots` | 经 `libbegetutil`（依赖 `init:libbegetutil`）读取的系统参数，提供 `numOfSlots` |
| proxy / stub / `shlib_type=hdi` / `ObjectCollector` | HDF IPC 机制；生成代码位于 `out/<product>/gen/drivers/interface/partitionslot/` |

## 3. 约束与边界（未经上报不得突破）

### 3.1 架构不变量（硬规则）

1. **bootctrl 磁盘布局是与 bootloader 的契约。** active slot @ 偏移 1024
   （4 字节）、unbootable slot @ 偏移 1028（4 字节）——即
   `MISC_PARTITION_*` 常量。绝不修改偏移/大小；bootloader 与 updater 都
   认这个格式。
2. **本部件的 IPC 签名已冻结。** 本部件只实现接口。签名/语义变更属于
   `drivers/interface/partitionslot`（IDL，独立仓库，有各自的评审规则）。
3. **槽位编号怪癖。** 实现（含测试）把 **2 当作 B 槽**
   （`UPDATE_PARTITION_B = 2`）：`GetSlotSuffix(2)` → `"_b"`，其余一律
   `"_a"`——而 IDL 注释写的是 0=A、1=B、N=N。绝不在此"顺手修复"；编号
   语义必须先与接口仓对齐。
4. **返回值契约。** 0 = 成功，负数 = 失败；`-1` 特指单板不支持 A/B 分区。
   注意：HAL 的 `GetCurrentSlot` 即使 bootctrl 读取失败也返回 0（此时
   `currentSlot` 为 -1）。

### 3.2 禁止事项

- 绝不修改 `MISC_PARTITION_*` 常量（§3.1.1）。
- 除非任务明确要求，不对真机执行 `SetActiveSlot` / `SetSlotUnbootable`
  （或单测用例 003/004）——它们改变持久化启动状态；用例 003 会恢复 active
  slot，用例 004 会留下已写入的不可启动标记。
- 不随意修改 `install_images`：hal 库 → system + updater 镜像；hdi_service
  两个库 → chipset 镜像。
- 不编辑 `out/<product>/gen/` 下的生成代码——应通过重新构建再生成。
- 新增源文件必须挂进对应 `BUILD.gn` 的 `sources`——否则静默不参与构建。
- 不删除 Apache 2.0 许可证头。

### 3.3 需先确认（Ask before）

- 对 `bundle.json` 的 `inner_kits` 或 `hal/include/` 头文件的任何修改——
  `libpartition_slot_manager` 会被下游部件链接。
- `SetActiveSlot` / `SetSlotUnbootable` 的任何语义变更——启动行为，需维护者
  拍板。
- 修改槽位编号（§3.1.3）——先与接口仓对齐。

### 3.4 本地约定

- `hal/BUILD.gn` 与 `hdi_service/BUILD.gn` 用长相对路径
  （`"../../../../drivers/peripheral/partitionslot/..."`）而非
  `//drivers/...` 标签引用本部件——编辑时保持本地风格。
- 日志：hal 用 hilog 宏（`HILOG_*`，LOG_DOMAIN 0xD002500，tag
  `hdf_partitionslot_manager`）；hdi_service 用 `HDF_LOG*`（tag
  `hdf_partitionslot_impl`）。
- 新文件需带 Apache 2.0 许可证头，与现有文件一致。

### 3.5 本处常见的 Agent 失败模式

- 在本目录运行 `build.sh`——只能在 OHOS 源码根目录（含 `build.sh` 的祖先
  目录）运行。
- 依 IDL 注释以为槽位 1 = B，而实现用的是 2。
- 期望单测脱离真机也能通过——它需要真实 HDF 环境和
  `/dev/block/by-name/bootctrl`；无设备时只能做编译/链接检查。

## 4. 验证闭环

### 4.1 构建部件（在 OHOS 源码根目录运行，不是本目录）

```bash
./build.sh --product-name rk3568 --build-target partitionslot_entry        # 全部件：hal + hdi_service
./build.sh --product-name rk3568 --build-target libpartition_slot_manager  # 仅 HAL inner_kit
./build.sh --product-name rk3568 --build-target hdf_partitionslot_service  # hdi_service 两个库
```

### 4.2 构建并运行单元测试

```bash
./build.sh --product-name rk3568 --build-target partitionslot_hdi_test
# 二进制：out/rk3568/tests/unittest/drivers_peripheral_partitionslot/drivers_peripheral_partition_slot/partitionslot_hdi_test
```

测试经 `IDeviceManager::LoadDevice("partition_slot_service")` 拉起服务，
通过 proxy 走真实 HDF IPC 驱动全部四个 API——需要带
`/dev/block/by-name/bootctrl` 的设备（或完整 HDF 环境）。仅构建该目标即
可端到端验证编译/链接链路。

### 4.3 宣布完成前的最低检查

- [ ] §4.2 命令 `--build-target partitionslot_hdi_test` 构建通过。
- [ ] `git diff` 未触碰任何 `MISC_PARTITION_*` 常量、`bundle.json` 的
      `inner_kits`、`install_images`（除非已获明确批准，见 §3.3）。
- [ ] 若改动了 HDI 行为：逐条说明 4 个测试用例的预期结果是否变化。
- [ ] 新文件已挂进 `BUILD.gn` 且带许可证头。
- [ ] 所改文件无新增编译告警。

### 4.4 完成判据与最终回复

报告：(1) 改了哪些文件，标注关键改动的 `path:line`；(2) 适用了 §3 的哪条
约束、如何遵守；(3) 实际运行的构建/测试命令及通过/失败结果。若无法运行
构建/测试（无工具链或设备），需明确说明，将工作标记为 `NOT VERIFIED`，并列
出应由人工执行的命令——不得在没有证据的情况下宣称成功。
