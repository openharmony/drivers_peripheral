# AGENTS.md - OpenHarmony 驱动宿主进程（Drivers Devhost）

## 1. 代码地图

本仓库是 HDF 驱动宿主进程（hdf_devhost）的入口点。`hdf_devhost` 是 OpenHarmony 中加载和管理所有 HDI 驱动的用户态进程，每个 hostId 对应一个 devhost 进程。本仓**仅包含进程入口（main 函数）**，实际服务实现在 `drivers/hdf_core` 的 `adapter/uhdf2/host/` 中。

### 非本项目维护的目录

以下内容属于其他团队，不属于本项目维护范围，修改时请跳过：

- `drivers/hdf_core/adapter/uhdf2/host/`：devhost 的核心服务实现（`libhdf_host`），由 HDF 框架团队维护
- vendor 仓的 init 配置文件（`.cfg`）：定义 devhost 进程的启动参数，由 vendor 团队维护
- `drivers/hdf_core/` 下的驱动加载、设备管理、电源管理框架代码

### 嵌套指引

本仓结构极简（仅 `host/devhost.c` 一个源文件），不建议新建嵌套 AGENTS.md。所有指引在本文件中维护。如需了解 `libhdf_host` 的内部实现，请参考 `drivers/hdf_core/adapter/uhdf2/host/` 目录。

### 关键区域

- `host/devhost.c`：唯一的源文件，包含 `main()` 函数。解析命令行参数（hostId、hostName、进程优先级、线程优先级），初始化 devhost 服务，设置电源管理
- `host/BUILD.gn`：构建配置，链接 `libhdf_host`（来自 `drivers/hdf_core`）
- `BUILD.gn`：顶层构建入口
- `bundle.json`：组件定义，组件名 `drivers_devhost`，版本 6.0

### Where to look

| 任务类型 | 先看哪里 |
|---|---|
| 进程启动流程 | `host/devhost.c` 的 `main()` 函数 |
| 命令行参数 | `host/devhost.c` 中的 `getopt` 解析逻辑 |
| 服务初始化 | `host/devhost.c` 调用的 `DevHostServiceFullInitialize` 等（实现在 hdf_core） |
| 进程管理 | `host/devhost.c` 中的 `prctl`、`setpriority` 调用 |
| dump 支持 | `host/devhost.c` 中的信号处理和 `DevhostDump` 调用 |

### 架构分层

```
init（系统 init 进程）
  └─ fork + exec hdf_devhost（本仓 host/devhost.c）
      ├─ 解析命令行参数（hostId, hostName, pri, threadPri）
      ├─ DevHostServiceFullInitialize（实现在 drivers/hdf_core）
      ├─ 设置进程优先级 / 线程优先级
      ├─ 注册 dump 信号处理
      └─ 进入主循环（加载和托管 HDI 驱动）
```

## 2. 知识路由

### Task-based routing

| 任务类型 | 读取 |
|---|---|
| 修改启动参数 | `host/devhost.c` 的 `main()` + init 配置（`init.cfg` 在 vendor 仓） |
| 修改进程优先级 | `host/devhost.c` 中 `setpriority` / `prctl` 调用 |
| 修改 dump 行为 | `host/devhost.c` 中信号处理逻辑 |
| 修改服务初始化 | `host/devhost.c` → `drivers/hdf_core/adapter/uhdf2/host/` |

### Path-based routing

| 修改路径 | 需了解的上下文 |
|---|---|
| `host/devhost.c` | 唯一源文件，任何修改影响**所有** HDI 驱动宿主进程 |
| `host/BUILD.gn` | 链接配置，变更需确认 `libhdf_host` 依赖 |
| `bundle.json` | 组件定义，依赖变更需同步 |

### Vocabulary-based routing

| 术语 | 含义与风险 | 读取 |
|---|---|---|
| hostId | 驱动宿主编号，每个编号对应一个 devhost 进程 | `host/devhost.c` |
| hostName | 驱动宿主名称，用于日志和调试 | `host/devhost.c` |
| devhost | 驱动宿主进程，托管所有 HDI 驱动服务 | 本仓 |
| libhdf_host | HDF 宿主共享库，devhost 的核心实现 | `drivers/hdf_core/adapter/uhdf2/host/` |

### 在计划阶段，必须声明

- **任务分类**（如：启动参数变更 / 进程优先级调整 / dump 行为变更 / 服务初始化变更 / 构建配置变更）
- **已读取的源文件**（`host/devhost.c` 具体到行号）
- **发现的约束**（架构不变量、禁止事项、init 契约、跨仓同步需求）
- **是否需要同步修改其他层**：
  - 命令行参数变更 → 同步 vendor 仓 init 配置（`.cfg` 文件）
  - 服务初始化变更 → 同步 `drivers/hdf_core/adapter/uhdf2/host/` 实现
  - 依赖变更 → 同步 `bundle.json` + `host/BUILD.gn`

## 3. 约束边界

### 架构不变量

- **本仓只做进程入口**：不要在此仓添加业务逻辑，业务实现在 `drivers/hdf_core`
- **devhost 是特权进程**：进程崩溃会导致所有托管的 HDI 驱动不可用
- **命令行参数是 init 契约**：参数顺序和含义由 init 配置决定，不能随意修改

### 禁止事项

- **不要在 `host/devhost.c` 中添加业务逻辑**：业务逻辑属于 `drivers/hdf_core`
- **不要修改命令行参数顺序**：init 脚本按固定位置传参
- **不要引入新的外部依赖**：本仓应保持最小依赖
- **不要跳过优先级设置**：进程/线程优先级影响所有驱动调度
- **不要手改 `drivers/hdf_core` 的框架代码**：本仓仅是入口，框架实现在 `drivers/hdf_core/adapter/uhdf2/host/`
- **不要忽略 Agent 失败模式**：常见 Agent 错误包括①在本仓添加业务逻辑（应放 `drivers/hdf_core`）②修改命令行参数顺序不同步 init 配置③引入不必要的依赖④跳过优先级设置导致调度异常

### Ask before 规则

在执行以下操作前，必须先确认或询问：
- **修改命令行参数顺序**：确认 init 配置 `.cfg` 文件同步更新
- **调整进程/线程优先级**：确认对所有驱动调度的影响
- **添加新依赖**：确认是否应放在 `drivers/hdf_core` 而非本仓

### 需确认后再修改

- **命令行参数变更**：需同步 init 配置（vendor 仓的 `.cfg` 文件）
- **进程/线程优先级调整**：需评估对系统调度的影响
- **新增依赖**：需确认是否应放在 `drivers/hdf_core` 而非本仓

### 项目特定陷阱

- **参数位置硬编码**：`DEVHOST_INPUT_PARAM_HOSTID_POS=1`、`DEVHOST_INPUT_NAME_POS=2` 等，修改需同步 init 传参
- **最小参数数检查**：`DEVHOST_MIN_INPUT_PARAM_NUM=5`，少于 5 个参数直接退出
- **dump 信号**：devhost 注册了信号处理用于 dump，修改信号处理需注意不要覆盖

## 4. 验证闭环

### 最小验证

```bash
# 构建 devhost
./build.sh --product-name rk3568 --build-target drivers_devhost

# 静态分析
cppcheck --enable=all --error-exitcode=1 host/ 2>/dev/null || true
clang-format --dry-run --Werror host/ 2>/dev/null || true
```

### 任务特定验证

| 任务类型 | 验证命令 |
|---|---|
| 启动参数变更 | 构建 devhost + 真机验证 init 拉起 + 检查 dmesg/hilog + 静态分析 |
| 优先级变更 | 构建 devhost + 真机验证进程调度 + 静态分析 |
| dump 变更 | 构建 devhost + 真机发送信号验证 dump 输出 + 静态分析 |

### Done 定义

- 构建通过（`drivers_devhost`）
- 无新增编译警告
- 无 lint/static analysis 违规（cppcheck/clang-format）
- 变更不影响 devhost 正常启动和驱动加载
- 命令行参数变更已同步 init 配置
- 无新增外部依赖

### 最终响应期望

完成报告必须包含：
1. 修改的文件清单（按 `file:line` 引用）
2. 任务分类与对应验证命令的执行结果（含 lint/static analysis 结果）
3. 是否触发跨仓同步修改（`drivers/hdf_core` / vendor 仓 init 配置 / `bundle.json`）
4. 是否影响 devhost 进程启动和驱动加载
5. 是否触及架构不变量或需确认事项

### 无法验证时

如果构建环境不可用，列出应执行的命令并说明预期结果，明确标注「未验证」字样，不能假称已通过。devhost 是特权进程，变更需真机验证 init 拉起和驱动加载，无法在沙箱完整验证。
