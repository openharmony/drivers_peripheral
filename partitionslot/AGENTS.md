# AGENTS.md — drivers/peripheral/partitionslot

Guidance for coding agents working in the OpenHarmony **drivers_peripheral_partitionslot**
component — the server-side implementation of the PartitionSlot HDI (A/B multi-slot
boot partition management). Read this before editing any file under
`drivers/peripheral/partitionslot/`.

> Scope: component root (`drivers/peripheral/partitionslot`), inside the
> `drivers/peripheral` git repository. The HDI interface (IDL, generated
> proxy/stub) lives in a separate repo: `drivers/interface/partitionslot`.

## 1. Code map

### 1.1 What this component owns

The PartitionSlot HDI service implementation, offering four APIs:
- `GetCurrentSlot` — which partition slot the board booted from, and how many slots exist,
- `GetSlotSuffix` — slot index → partition-name suffix (`"_a"` / `"_b"`),
- `SetActiveSlot` — switch the slot the device boots from next,
- `SetSlotUnbootable` — mark a slot unbootable.

Slot state is persisted directly in the bootctrl partition
(`/dev/block/by-name/bootctrl`); the slot count comes from the system parameter
`ohos.boot.bootslots` (default 1). Typical consumer: the `begetctl partitionslot`
tool in `base/startup/init` (`services/begetctl/partitionslot.cpp`, subcommands
`getslot` / `getsuffix` / `setactive` / `setunboot`; `setactive` is listed in
that repo's AGENTS.md as a destructive command).

### 1.2 Runtime call chain (dependency direction: top calls bottom; never reverse)

```
caller (e.g. begetctl partitionslot in startup_init)
  → libpartitionslot_proxy_1.0        generated proxy (drivers/interface repo)
  → HDF dispatch in partitionslot_host  HdfSBuf ↔ MessageParcel, forwards to stub
  → PartitionSlotImpl                  implements IPartitionSlot (libpartition_slot_service_1.0)
  → PartitionSlotManager               DelayedSingleton, all real logic (libpartition_slot_manager)
  → /dev/block/by-name/bootctrl        raw open/lseek/read/write
```

| Path | Product | Role |
| --- | --- | --- |
| `hal/src/partitionslot_manager.cpp` | `libpartition_slot_manager` (inner_kit; system + updater images) | Bootctrl I/O, system parameter read |
| `hdi_service/src/partitionslot_impl.cpp` | `libpartition_slot_service_1.0` (chipset image) | IDL method impls; exports `extern "C" PartitionSlotImplGetInstance` for HDI framework dlsym |
| `hdi_service/src/partition_slot_driver.cpp` | `libpartitionslot_driver` (`shlib_type=hdi`; chipset image) | `HdfDriverEntry` (moduleName `partitionslot_interface_service`); Bind wires stub via `ObjectCollector` |
| `test/unittest/hdf_partitionslot_test.cpp` | `partitionslot_hdi_test` | On-device gtest (HWTEST_F), one case per API |
| `BUILD.gn` / `bundle.json` | — | Top group `partitionslot_entry`; inner_kits declaration |

Deployment comes from per-product HDF config (`vendor/<vendor>/<product>/hdf_config/uhdf/device_info.hcs`,
section `partitionslot`): host `partitionslot_host`, service name
`partition_slot_service`, driver `libpartitionslot_driver.z.so`, `preload = 2`
(on-demand — `IPartitionSlot::Get(true)` triggers the load). The host process
uid/gid also comes from this config (rk3568: uid `useriam`, gid
`["useriam", "update"]`) — check it when debugging bootctrl permission errors.

High-risk / frequently-changed paths (treat changes here with extra care):
`hal/src/partitionslot_manager.cpp` (`MISC_PARTITION_*` disk-layout constants,
slot numbering), `bundle.json` (`inner_kits` is the downstream-facing surface).

Nested guidance: none in this component. The interface side has its own
`drivers/interface/partitionslot/AGENTS.md` (ZH mirror `AGENTS_zh.md`).

## 2. Knowledge routing — read before you edit

Before editing any file, state to yourself: (1) the task category, (2) which row
of §2.1 you loaded (plus the IDL row whenever API semantics are involved), and
(3) which §3 constraint applies. If you cannot answer all three, stop and read.

### 2.1 Task-based routing

| Working on / task | Read this first | Key concept to load |
| --- | --- | --- |
| Bootctrl read/write, system parameter | `hal/src/partitionslot_manager.cpp` | Active slot @ offset 1024 (4 B), unbootable @ 1028 (4 B); `ohos.boot.bootslots` |
| HDI method behavior, service loading | `hdi_service/src/partitionslot_impl.cpp` | `PartitionSlotImplGetInstance` is the dlsym entry; `IPartitionSlot::Get(true)` loads the service |
| Driver registration, dispatch, stub wiring | `hdi_service/src/partition_slot_driver.cpp` | `HdfDriverEntry` Bind/Init/Release; `SbufToParcel`; `ObjectCollector::GetOrNewObject` |
| Test cases / expectations | `test/unittest/hdf_partitionslot_test.cpp` | `IDeviceManager::LoadDevice("partition_slot_service")`; case 003 flips the active slot and restores it; case 004 marks slot 2 unbootable and does **not** restore |
| API semantics, parameter direction, signatures | `drivers/interface/partitionslot/v1_0/IPartitionSlot.idl` + its `AGENTS.md` | Return-value contract; versioning rules |
| Host / service name / load policy | `vendor/<vendor>/<product>/hdf_config/uhdf/device_info.hcs` (`partitionslot` section) | `preload = 2` on-demand loading |

### 2.2 Vocabulary routing (when a term appears in a task/log/issue/API)

| Term / acronym | Concept |
| --- | --- |
| slot, A/B partition, active slot, unbootable, slot suffix | Defined per method in `IPartitionSlot.idl`; numbering quirk in §3.1.3 |
| bootctrl | The misc-style partition holding slot state; layout constants in `hal/src/partitionslot_manager.cpp` |
| `bootslots` | System parameter read via `libbegetutil` (`init:libbegetutil` dependency) providing `numOfSlots` |
| proxy / stub / `shlib_type=hdi` / `ObjectCollector` | HDF IPC machinery; generated code lives under `out/<product>/gen/drivers/interface/partitionslot/` |

## 3. Constraints and boundaries (do not break without escalation)

### 3.1 Architecture invariants (hard rules)

1. **The bootctrl disk layout is a bootloader contract.** Active slot @ offset
   1024 (4 bytes), unbootable slot @ offset 1028 (4 bytes) — the
   `MISC_PARTITION_*` constants. Never change offsets/sizes; bootloader and
   updater agree on this format.
2. **IPC signatures are frozen here.** This component only implements the
   interface. Signature/semantic changes belong in
   `drivers/interface/partitionslot` (IDL, separate repo, own review rules).
3. **Slot numbering quirk.** The implementation (and tests) treat **2 as slot B**
   (`UPDATE_PARTITION_B = 2`): `GetSlotSuffix(2)` → `"_b"`, everything else →
   `"_a"` — while the IDL docs say 0=A, 1=B, N=N. Never "fix" this locally;
   numbering semantics must be aligned with the interface repo first.
4. **Return-value contract.** 0 = success, negative = failure; `-1` specifically
   means the board does not support A/B partitions. Note: HAL `GetCurrentSlot`
   returns 0 even when the bootctrl read fails (`currentSlot` is then -1).

### 3.2 Do-not rules

- Do **not** modify the `MISC_PARTITION_*` constants (§3.1.1).
- Do **not** run `SetActiveSlot` / `SetSlotUnbootable` (or unittest cases
  003/004) against real hardware unless the task explicitly asks — they change
  persistent boot state; case 003 restores the active slot, case 004 leaves the
  unbootable mark written.
- Do **not** change `install_images` casually: hal lib → system + updater
  images; both hdi_service libs → chipset image.
- Do **not** edit generated code under `out/<product>/gen/` — regenerate by
  building instead.
- Do **not** add a source file without wiring it into the matching `BUILD.gn`
  `sources` — it is silently not built otherwise.
- Do **not** remove the Apache 2.0 license header.

### 3.3 Ask before

- Any change to `bundle.json` `inner_kits` or headers under `hal/include/` —
  `libpartition_slot_manager` is linked by downstream components.
- Any semantic change to `SetActiveSlot` / `SetSlotUnbootable` — boot behavior,
  needs maintainer sign-off.
- Changing slot numbering (§3.1.3) — align with the interface repo.

### 3.4 Local conventions

- `hal/BUILD.gn` and `hdi_service/BUILD.gn` reference this component via long
  relative paths (`"../../../../drivers/peripheral/partitionslot/..."`) instead
  of `//drivers/...` labels — keep the local style when editing.
- Logging: hal uses hilog macros (`HILOG_*`, LOG_DOMAIN 0xD002500, tag
  `hdf_partitionslot_manager`); hdi_service uses `HDF_LOG*` (tag
  `hdf_partitionslot_impl`).
- New files need the Apache 2.0 header, matching existing files.

### 3.5 Common agent failure modes here

- Running `build.sh` from this directory — it only works from the OHOS source
  root (ancestor containing `build.sh`).
- Assuming slot 1 = B from the IDL docs while the implementation uses 2.
- Expecting the unittest to pass off-device — it needs a real HDF environment
  and `/dev/block/by-name/bootctrl`; without a device only compile/link checks
  are possible.

## 4. Verification loop

### 4.1 Build the component (from the OHOS source root, not this directory)

```bash
./build.sh --product-name rk3568 --build-target partitionslot_entry        # everything: hal + hdi_service
./build.sh --product-name rk3568 --build-target libpartition_slot_manager  # HAL inner_kit only
./build.sh --product-name rk3568 --build-target hdf_partitionslot_service  # both hdi_service libs
```

### 4.2 Build & run unit tests

```bash
./build.sh --product-name rk3568 --build-target partitionslot_hdi_test
# binary: out/rk3568/tests/unittest/drivers_peripheral_partitionslot/drivers_peripheral_partition_slot/partitionslot_hdi_test
```

The test loads the service via `IDeviceManager::LoadDevice("partition_slot_service")`
and drives all four APIs through the proxy over real HDF IPC — it requires a
device (or full HDF environment) with `/dev/block/by-name/bootctrl`. Building
the target alone already verifies the compile/link chain end to end.

### 4.3 Minimum checks before declaring done

- [ ] `--build-target partitionslot_hdi_test` build succeeds (§4.2 command).
- [ ] `git diff` touches no `MISC_PARTITION_*` constant, no `bundle.json`
      `inner_kits`, no `install_images` (unless explicitly approved, §3.3).
- [ ] If HDI behavior changed: state for each of the 4 test cases whether the
      expected result changes.
- [ ] New files are wired into `BUILD.gn` and carry the license header.
- [ ] No new compile warnings in the files you touched.

### 4.4 Done definition & final response

Report: (1) files changed with `path:line` of the key edits, (2) which §3
constraint applied and how it was respected, (3) the exact build/test commands
run and their pass/fail result. If the build/tests could not run (no toolchain
or device), say so explicitly, mark the work `NOT VERIFIED`, and list the
commands a human should run instead — do not claim success without evidence.
