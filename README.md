# ProbePoint

这是一个面向嵌入式调试的嵌入式调试与探针工具链。长期目标是提供调试协议编解码、断点与观察点、单步与栈回溯、符号解析、内存与寄存器读写、跟踪缓冲和性能计数，把调试探针沉淀为可复用工具链。

仓库采用 Python，当前冻结基线只提供进程健康检查。后续能力必须通过独立题目逐步实现；每个题目都应定义可观察的公共行为、兼容边界和失败语义，不得依赖未公开内部 API。

## 启动

```bash
PYTHONPATH=src python3 -m probepoint.server --host 127.0.0.1 --port 8080
```

服务默认监听 `127.0.0.1:8080`，可通过 `PROBEPOINT_ADDR` 修改。`GET /healthz` 返回 JSON 健康状态。

## 调试协议帧编解码（v1）

帧采用网络字节序：两字节魔数 `0x5050`、一字节版本 `1`、一字节 flags、四字节 sequence、两字节 opcode、两字节 payload 长度、payload（0–4096 字节）、四字节 CRC-32/ISO-HDLC（覆盖版本号至 payload 末尾）。

- `POST /v1/frames/encode`：请求体为 `{"flags": u8, "sequence": u32, "opcode": u16, "payload": "<偶数位十六进制>"}`，成功返回 `{"frame": "<完整帧小写十六进制>"}`。
- `POST /v1/frames/decode`：请求体为 `{"frame": "<十六进制>"}`，成功返回 `{"version", "flags", "sequence", "opcode", "payload"}`。
- `POST /v1/frames/decode-stream`：无状态的流解码。请求体为 `{"data": "<偶数位十六进制，解码后不超过 1048576 字节>", "eof": bool}`，用于处理串口或 TCP 分段数据；调用方将上次返回的 `remainder` 与新数据拼接后再次提交，服务端不保存会话。返回 `{"frames", "errors", "discarded", "remainder"}`：`frames` 按出现顺序排列，字段与单帧解码相同并增加 `offset`（魔数在本次 data 中从零开始的字节偏移）；`errors` 按 `offset` 升序，每项只含 `offset` 与 `code`；`discarded` 为未组成合法帧且未进入 `remainder` 的字节数；`remainder` 为小写十六进制，只保留等待后续数据才能判断的末尾（`eof=true` 时为空字符串）。空 `data` 合法，返回两个空数组、`0` 和空字符串。

解析从左向右寻找魔数 `0x5050`，魔数之前的噪声计入 `discarded`。候选头完整后版本错误记 `unsupported_version`、声明长度超过 4096 记 `invalid_length`，完整候选校验失败记 `checksum_mismatch`；这些错误不终止请求，而是从魔数后的下一字节继续搜索后续合法帧，被跳过内容计入 `discarded`。候选数据不足且 `eof=false` 时从魔数起整体放入 `remainder` 且不报错，末尾单独的 `0x50` 也作为潜在魔数保留；`eof=true` 时相同情况记 `truncated_frame`，其余不能构成魔数的尾部作为噪声丢弃。序列号可重复，不去重、不排序。

请求体非法返回 `error.code=invalid_request`；字段缺失、多余、类型或取值错误返回 `invalid_field`；单帧解码失败按优先级返回 `truncated_frame`、`bad_magic`、`unsupported_version`、`invalid_length`、`trailing_data`、`checksum_mismatch`，均为 HTTP 400。

## 通道复用帧流（debug / serial / log）

调试、串口与日志三类数据共用上述 v1 帧流，通道与 opcode 固定映射：`debug` 为 `0x0001`、`serial` 为 `0x0002`、`log` 为 `0x0003`，帧 flags 固定为零。这两个入口只做离线编解码，不连接目标、不保存会话。

- `POST /v1/channels/encode`：请求体为 `{"channel": "debug"|"serial"|"log", "sequence": u32, "data": "<偶数位十六进制>"}`。`data` 解码后可为空、最多 4096 字节且字节保持原序，sequence 原样写入。成功返回 HTTP 200 与仅含小写完整帧十六进制的 `{"frame": "..."}`。
- `POST /v1/channels/decode-stream`：无状态的流解码。请求体仅含 `{"data": "<偶数位十六进制，解码后不超过 1048576 字节>", "eof": bool}`，调用方将上次返回的 `remainder` 与新数据拼接后再次提交，服务端不保存会话。返回对象仅含 `events`、`errors`、`discarded`、`remainder`：`events` 按帧起始 `offset` 升序，每项只含 `offset`、`channel`、`sequence` 与小写 `data`，重复 sequence 保留；`errors` 每项只含 `offset` 与 `code`。空 `data` 返回两个空数组、`0` 和空字符串。

流解析沿用 v1 帧的校验、错误代码、坏候选重同步、噪声计数及尾部语义（`truncated_frame`、`unsupported_version`、`invalid_length`、`checksum_mismatch`）。校验通过的帧 flags 非零时报告 `unsupported_flags`；flags 为零但 opcode 不在三种通道映射内时报告 `unsupported_channel`；两者同时出现只报告 `unsupported_flags`。这两类帧不生成事件，整帧字节计入 `discarded`，并从该帧之后继续解析。`eof=false` 时不完整候选写入小写 `remainder` 且不报错，`eof=true` 时报告 `truncated_frame` 并清空 `remainder`。

请求体无法解析为 JSON 对象返回 HTTP 400 `invalid_request`；字段缺失、多余、类型错误、未知 `channel`、整数越界、非法十六进制或数据超限返回 HTTP 400 `invalid_field`。

## ARM ITM 跟踪流解码

源数据包头字节：低两位为载荷长度码（1/2/3 对应 1/2/4 字节），第三位为来源（0 软件、1 硬件），高五位为端口号 0–31。`0x00` 为填充，至少五个 `0x00` 后接 `0x80` 组成同步包，`0x70` 为溢出包。

- `POST /v1/trace/itm/decode-stream`：无状态的流解码，不连接目标、不修改断点状态。请求体为 `{"data": "<偶数位十六进制，解码后不超过 1048576 字节>", "eof": bool}`，调用方将上次返回的 `remainder` 与新数据拼接后再次提交，服务端不保存会话。返回 `{"events", "errors", "discarded", "remainder"}`：`events` 按 `offset`（首字节在本次 data 中从零开始的偏移）升序，源事件含 `offset`、`type=source`、`source`、`port`、`size` 与原序小写 `data`，同步与溢出事件只含 `offset` 与 `type`；`errors` 按 `offset` 升序，每项只含 `offset` 与 `code`；`discarded` 为填充与错误消耗的字节数，不含成功事件与 `remainder`；`remainder` 为小写十六进制。空 `data` 合法，返回两个空数组、`0` 和空字符串。

解析从左向右进行。不足五个零后接的 `0x80` 以及其余低两位为 0 的字节记 `unsupported_packet`（消耗的字节计入 `discarded`），从下一字节继续；流内错误随 HTTP 200 返回，不阻断后续合法事件。载荷不足且 `eof=false` 时从头字节起进入 `remainder`，不报错；`eof=true` 时记 `truncated_packet`，候选计入 `discarded` 且 `remainder` 为空。末尾零串在 `eof=false` 时最多保留最后五个作为潜在同步前缀，多余部分计入 `discarded`；`eof=true` 时全部丢弃。

请求体非法返回 `error.code=invalid_request`（HTTP 400）；字段缺失、多余、类型错误、非法十六进制或 `data` 超限返回 `invalid_field`（HTTP 400）。

## GDB RSP 数据包编解码

线上数据包布局：`0x24`（`$`）+ 线上载荷 + `0x23`（`#`）+ 两位小写十六进制校验和。载荷中的 `0x24`、`0x23`、`0x7d`、`0x2a` 一律转义为 `0x7d` 后跟原值异或 `0x20`；校验和为转义后线上载荷字节之和模 256。

- `POST /v1/rsp/encode`：请求体为 `{"payload": "<偶数位十六进制>"}`，载荷可为空、上限 4096 字节，成功返回 `{"packet": "<完整数据包小写十六进制>"}`。
- `POST /v1/rsp/decode-stream`：无状态的流解析。请求体为 `{"data": "<偶数位十六进制，解码后不超过 1048576 字节>", "eof": bool}`，调用方将上次返回的 `remainder` 与新数据拼接后再次提交。返回 `{"packets", "controls", "errors", "discarded", "remainder"}`：`packets` 每项只含 `offset`（起始 `0x24` 在本次 data 中从零开始的字节偏移）与解转义后的小写 `payload`；候选之外的 `0x2b`、`0x2d` 生成 `{"offset", "type": "ack"|"nack"}` 控制项，其余噪声计入 `discarded`；`errors` 每项只含 `offset` 与 `code`。三个数组均按 `offset` 升序。空 `data` 合法，返回三个空数组、`0` 和空字符串。

解析从左向右进行。候选包内出现未转义 `0x24` 时旧候选记 `nested_start` 并从新位置重启；校验字符非法记 `invalid_checksum`，校验不符记 `checksum_mismatch`，解转义载荷超过 4096 字节记 `invalid_length`；失败候选的字节计入 `discarded` 后继续解析，不阻断后续数据包（包级错误均返回 HTTP 200）。候选缺少 `0x23`、校验字符不足两位或末尾只有 `0x7d` 且 `eof=false` 时，从起始 `0x24` 起原样进入小写 `remainder`，不报错也不丢弃；`eof=true` 时相同情况记 `truncated_packet`，全部丢弃且 `remainder` 为空。

请求体不是合法 JSON 对象返回 `invalid_request`（HTTP 400）；字段缺失、多余、类型或十六进制格式错误、`eof` 非布尔值、`data` 超限返回 `invalid_field`（HTTP 400）。

## GDB RSP 内存/寄存器命令与回复

以下两个入口在命令载荷层工作，不连接目标、不保存会话：`encode` 产出的 `payload` 可直接交给 `/v1/rsp/encode` 打包；`decode-response` 消费 `/v1/rsp/decode-stream` 解出的包内 `payload`。命令数值均为无前导零的小写十六进制，写入数据字节顺序保持不变。

- `POST /v1/rsp/commands/encode`：按 `operation` 编码 ASCII RSP 命令载荷，成功返回 `{"payload": "<小写十六进制>"}`。
  - `read_memory`：字段 `{"operation", "address", "length"}`，编码为 `m<address>,<length>`。`address` 为 u32，`length` 为 1 至 4096。
  - `write_memory`：字段 `{"operation", "address", "data"}`，编码为 `M<address>,<长度>:<data>`。`data` 为 1 至 4096 字节的偶数位十六进制。
  - `read_register`：字段 `{"operation", "register"}`，编码为 `p<register>`；`register` 为 u16。
  - `write_register`：字段 `{"operation", "register", "value"}`，编码为 `P<register>=<value>`；`value` 为 1 至 32 字节的偶数位十六进制。
  - `continue`：字段 `{"operation", "address"?}`，编码为 `c`（省略 `address`）或 `c<address>`；`single_step` 同理编码为 `s`/`s<address>`。`address` 为 u32，序列化为无前导零的小写十六进制（0 编码为 `0`）。
  - 内存访问要求 `address` 加访问字节数不越过 `0xffffffff`（即字节范围必须完整落在 32 位地址空间内），越界返回 `invalid_field`。
- `POST /v1/rsp/commands/decode-response`：解释目标回复载荷，字段为 `{"operation", "payload", ...}`；`read_memory` 必须携带 `expected_length`（1 至 4096），`read_register` 必须携带 `expected_size`（1 至 32），写操作与 `continue`/`single_step` 不得携带这两个字段。内存/寄存器结果：
  - 空载荷返回 `{"status": "unsupported"}`。
  - `E` 加两位十六进制错误码返回 `{"status": "error", "code": "<小写两位码>"}`。
  - 读取成功返回 `{"status": "ok", "data": "<小写十六进制>"}`（内存）或 `{"status": "ok", "value": "<小写十六进制>"}`（寄存器），内容长度必须与期望值一致。
  - 写入成功只接受 ASCII `OK`，返回 `{"status": "ok"}`。

`continue` 与 `single_step` 的回复（一次请求只解释一个流入口取出的 payload）：

  - 空载荷与 `E` 错误码沿用上面的 `unsupported` 与 `error` 结果。
  - `S` 加两位十六进制信号值返回 `{"status": "stopped", "signal": "<小写两位>", "details": []}`。
  - `T` 同样返回 `stopped`，信号值规范为小写；信号之后以分号分隔的非空 ASCII `key:value` 字段按原顺序写入 `details`，每项为 `{"key": "原始键", "value": "原始值"}`；允许末尾分号，重复键保留。
  - `W` 加两位十六进制状态码返回 `{"status": "exited", "code": "<小写两位>"}`。
  - `X` 加两位十六进制信号值返回 `{"status": "terminated", "signal": "<小写两位>"}`。
  - `O` 后跟偶数位十六进制数据返回 `{"status": "console", "data": "<小写十六进制>"}`，允许空数据。

请求体不是合法 JSON 对象返回 `invalid_request`（HTTP 400）；字段缺失、多余、类型或取值范围错误、十六进制格式错误、写操作或执行操作携带期望长度、`continue`/`single_step` 的 `address` 类型或范围错误返回 `invalid_field`（HTTP 400）；回复含非法字符、被截断、长度与期望不符，成功形式与 `operation` 不符（如读取收到 `OK`、写入收到数据），或执行回复出现未知前缀、`OK`、位数错误/含非十六进制内容的 `S`/`T`/`W`/`X`/`E`、奇数位或非十六进制的 `O` 数据、`T` 字段缺少冒号、键或值为空、含非 ASCII 内容，返回 `invalid_response`（HTTP 400）。

## 离线栈回溯（ARM Cortex-M）

`POST /v1/backtrace` 根据停机快照离线展开小端 32 位帧指针链，不连接目标、不保存会话，也不修改断点状态。请求体为 `{"pc": u32, "sp": u32, "frame_pointer": u32, "stack_base": u32, "stack": "<偶数位十六进制，解码后不超过 1048576 字节>", "symbols": [...], "max_frames"?: 1..256}`；`max_frames` 缺省为 64。`stack` 是地址从 `stack_base` 开始的内存快照，其覆盖区间不得越过 `0xffffffff`。`symbols` 每项为 `{"name": "<非空字符串>", "start": u32, "end": u32}`，区间须满足 `start < end` 且互不重叠（相邻允许）。

成功返回 HTTP 200 与 `{"frames", "stop_reason"}`。首帧地址为 `pc` 清除最低 Thumb 位后的值，`sp` 与 `frame_pointer` 取输入值；之后在当前帧指针处读取 8 字节小端记录，前四字节为上一帧指针、后四字节为保存的 LR，调用者地址为 LR 清除最低位，`sp` 为当前帧指针加 8。每帧含 `level`、`address`、`sp`、`frame_pointer`、`symbol`、`offset`；地址落入某符号的 `start <= address < end` 区间时给出符号名与相对偏移，否则 `symbol` 与 `offset` 为 JSON `null`。

`stop_reason` 取值：帧指针归零为 `complete`；达到 `max_frames` 上限为 `max_frames`；指针未四字节对齐、链条未严格向高地址推进或成环为 `invalid_chain`（保留已完成帧）；记录未完整落入快照为 `stack_exhausted`。不会输出只读取一部分的帧。

请求体不是合法 JSON 对象返回 `invalid_request`（HTTP 400）；字段缺失、多余、类型或范围错误、非法十六进制、栈地址溢出、非法或重叠符号区间返回 `invalid_field`（HTTP 400）。结构合法但无法继续展开时只按上述 `stop_reason` 返回部分结果（HTTP 200）。

## 固件符号解析（ELF 符号表）

`POST /v1/symbols/resolve` 是无状态入口：调用方在请求中提交 ARM 固件 ELF 与一组地址，服务端返回函数名与偏移，不保存 ELF 或结果，也不修改断点状态。请求体为 `{"elf": "<偶数位十六进制，解码后不超过 4194304 字节>", "addresses": [u32, ...], "include_local": bool}`；`addresses` 包含 1 至 256 项，按输入顺序处理并保留重复值。

入口只接受 ELF32、小端、`EM_ARM` 文件，解析节头表以及 `SHT_SYMTAB`、`SHT_DYNSYM` 两类符号表及其链接的字符串表。仅使用已定义（`st_shndx != SHN_UNDEF`）、名称非空且 `st_size` 非零的 `STT_FUNC` 符号；`include_local=false` 时排除 `STB_LOCAL` 绑定的符号。查询地址与符号起点都先清除最低 Thumb 位，命中条件为 `start <= address < start + size`。多个符号同时命中时依次按以下次序选择：起点最大优先；起点相同时绑定 `STB_GLOBAL` 高于 `STB_WEAK` 高于 `STB_LOCAL`；再相同时范围（大小）更小优先；仍相同时符号表所在节序号更小、表内序号更小优先。

成功返回 HTTP 200 与 `{"results": [...]}`，每项保留原始 `address`；命中时另含 `name`、`symbol_address`（清除 Thumb 位后的起点）、`offset`、`size`、`binding`（`global`/`weak`/`local`），未命中时这五项均为 JSON `null`。

错误语义：损坏或截断的 ELF、越界的节或字符串引用、候选名称不是有效 UTF-8、符号范围越过 32 位地址空间返回 HTTP 400 `invalid_elf`；ELF 类别（非 ELF32）、字节序（非小端）或机器类型（非 `EM_ARM`）不支持返回 HTTP 422 `unsupported_elf`；两类符号表均不存在返回 HTTP 422 `symbol_table_not_found`。请求体不是合法 JSON 对象返回 `invalid_request`；字段缺失、多余、类型错误、非法十六进制、ELF 大小或地址数量越界返回 `invalid_field`，均为 HTTP 400。

## 周期计数耗时分析（Cortex-M DWT CYCCNT）

`POST /v1/performance/cycles/analyze` 是无状态入口：调用方提交已采集的 DWT CYCCNT 起止快照，服务端换算周期数与耗时，不连接目标、不读取硬件，也不保存任何采样数据。请求体仅含 `{"clock_hz": 1..4294967295, "samples": [...]}`，`samples` 包含 1 至 4096 项，每项仅含 `{"label": "<字符串>", "start": u32, "end": u32}`。`label` 去除首尾 Unicode 空白后须为 1 至 64 个字符，规范化后允许重复；`start`、`end` 均为无符号 32 位整数，布尔值不接受为整数。

一次测量最多跨越一次回卷：`end >= start` 时 `cycles = end - start`、`wrapped = false`；否则 `cycles = 2^32 - start + end`、`wrapped = true`。成功返回 HTTP 200 与 `{"samples": [...], "summary": [...]}`。`samples` 按输入顺序保留重复项，每项含规范化 `label`、原始 `start`、`end`、`cycles`、`wrapped`，以及 `duration_ns = floor(cycles × 1000000000 ÷ clock_hz)`。全部计算使用整数，JSON 数值不会输出浮点数或科学计数法。

`summary` 按规范化 `label` 首次出现顺序聚合，每项含 `label`、`count`、`total_cycles`、`min_cycles`、`max_cycles`、`average_cycles`、`total_duration_ns`、`average_duration_ns`；`total_duration_ns` 为各项 `duration_ns` 之和，`average_cycles` 与 `average_duration_ns` 分别用对应总值除以 `count` 后向下取整。

错误语义：请求体不是合法 JSON 对象返回 `invalid_request`（HTTP 400）；字段缺失或多余、类型错误（含布尔值冒充整数）、数值越界、非法 `label` 或 `samples` 数量越界返回 `invalid_field`（HTTP 400），且不返回任何部分结果。

## Cortex-M 故障快照诊断（ARMv7-M）

`POST /v1/faults/cortex-m/analyze` 是无状态入口：调用方提交异常发生时的基本栈帧与故障状态寄存器快照，服务端离线解码，不连接目标、不读取硬件，也不改变断点或会话状态。请求体仅含 `{"stacked_frame": "<偶数位十六进制>", "cfsr": u32, "hfsr": u32, "mmfar": u32, "bfar": u32}`；布尔值不接受为整数。`stacked_frame` 解码后必须恰好为 32 字节，按小端 `u32` 依次为 `r0`、`r1`、`r2`、`r3`、`r12`、`lr`、`pc`、`xpsr`。

成功返回 HTTP 200 与 `{"frame", "status", "primary", "causes", "fault_addresses"}`。`frame` 含上述八个寄存器、`instruction_address`（`pc` 清除最低 Thumb 位后的值）以及 `frame_valid`（由 xPSR 的 T 位、即第 24 位决定）；T 位未置位时仍返回完整结果，仅 `frame_valid` 为 `false`。`status` 原样回显 `{"cfsr", "hfsr"}`。

`causes` 先按 CFSR 位号、再按 HFSR 位号升序排列，每项仅含 `register`、`bit`、`name`。识别的 CFSR 位：MMFSR 的 IACCVIOL(0)、DACCVIOL(1)、MUNSTKERR(3)、MSTKERR(4)、MLSPERR(5)；BFSR 的 IBUSERR(8)、PRECISERR(9)、IMPRECISERR(10)、UNSTKERR(11)、STKERR(12)、LSPERR(13)；UFSR 的 UNDEFINSTR(16)、INVSTATE(17)、INVPC(18)、NOCP(19)、UNALIGNED(24)、DIVBYZERO(25)。识别的 HFSR 位：VECTTBL(1)、FORCED(30)、DEBUGEVT(31)。MMARVALID(7) 与 BFARVALID(15) 只用于门控地址，不进入 `causes`；未定义位只保留在 `status` 原样回显中。`primary` 按 `memmanage`、`busfault`、`usagefault`、`hardfault` 的顺序取首个存在原因的类别，均无原因时为 `none`。

`fault_addresses` 固定含 `mmfar`、`bfar` 两个键：仅当 CFSR 的 MMARVALID/BFARVALID 位置位时分别返回对应地址，否则该键为 JSON `null`。

错误语义：请求体不是合法 JSON 对象返回 `invalid_request`（HTTP 400）；字段缺失或多余、类型或范围错误（含布尔值冒充整数）、非法十六进制、栈帧长度错误返回 `invalid_field`（HTTP 400），不返回部分结果。

## 断点与观察点（v1）

记录仅保存在当前服务进程中，重启后为空，不产生任何持久化副作用。id 为按创建顺序递增的正整数，同一进程内不复用；返回对象包含全部规范化字段（execute 无 `size`，其他类型带 `size`）。

- `POST /v1/breakpoints`：请求体为 `{"kind": "execute"|"read"|"write"|"access", "address": u32, "enabled": bool, "size"?: 1|2|4|8}`。`execute` 不得携带 `size`；`read`/`write`/`access` 必须携带 `size`，且 `address` 按 `size` 对齐。成功返回 HTTP 201 与 breakpoint 对象。
- `GET /v1/breakpoints`：返回按 id 升序的 breakpoint 对象数组；可用 `kind` 与 `enabled=true|false` 查询参数联合筛选。未知参数、重复参数或非法值返回 `invalid_query`（HTTP 400）。
- `PATCH /v1/breakpoints/{id}`：请求体只能为 `{"enabled": bool}`，返回更新后的对象。
- `DELETE /v1/breakpoints/{id}`：返回 HTTP 200 与 `{"deleted": id}`。

错误语义：请求体不是合法 JSON 对象返回 `invalid_request`；字段缺失、多余、类型错误、数值越界、execute 携带 size、观察点缺少 size 或地址未对齐返回 `invalid_field`（字段校验先于重复检查）；`kind`、`address`、`size` 相同的记录视为重复（与启用状态无关），返回 HTTP 409 `duplicate_breakpoint`；不存在的正整数 id 返回 HTTP 404 `breakpoint_not_found`；路径 id 不是十进制正整数返回 HTTP 400 `invalid_breakpoint_id`。

## 多目标调试会话（v1）

会话仅存在于当前服务进程：重启后清空，不落盘。每个会话持有独立的断点集合，断点 id 在各会话内分别从 1 递增，不同会话可保存相同记录；全局 `/v1/breakpoints` 集合不受影响。会话 id 从 1 递增，删除后不复用。

- `POST /v1/sessions`：请求体仅含 `{"name": "<字符串>"}`；`name` 去除首尾 Unicode 空白后须为 1 至 64 个字符，存活会话的规范化名称大小写敏感且唯一。成功返回 HTTP 201 与只含 `id`、`name` 的对象。
- `GET /v1/sessions`：按 id 升序返回存活会话数组，每项只含 `id`、`name`。
- `DELETE /v1/sessions/{id}`：原子地删除会话及其全部断点，返回 `{"deleted": id}`。
- `POST|GET /v1/sessions/{id}/breakpoints` 与 `PATCH|DELETE /v1/sessions/{id}/breakpoints/{breakpoint_id}`：行为、字段、筛选、状态码与错误语义同全局 `/v1/breakpoints`。

错误语义：创建请求体不是合法 JSON 对象返回 `invalid_request`；字段缺失、多余、类型错误、规范化名称为空或超长返回 `invalid_field`；名称重复返回 HTTP 409 `duplicate_session`；会话 id 不是无前导零的十进制正整数返回 `invalid_session_id`，不存在或已删除返回 HTTP 404 `session_not_found`；嵌套的 breakpoint id 沿用 `invalid_breakpoint_id`。删除会话后其所有相关操作返回 `session_not_found`，已删除数据不会重新出现。

## 验证

```bash
PYTHONPATH=src python3 -m unittest discover -s tests -v
```

内存与寄存器读写、跟踪缓冲等后续能力仍刻意未实现，以便后续任务从已冻结事实出发独立设计并验证这些能力。
