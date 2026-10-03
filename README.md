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

## 断点与观察点（v1）

记录仅保存在当前服务进程中，重启后为空，不产生任何持久化副作用。id 为按创建顺序递增的正整数，同一进程内不复用；返回对象包含全部规范化字段（execute 无 `size`，其他类型带 `size`）。

- `POST /v1/breakpoints`：请求体为 `{"kind": "execute"|"read"|"write"|"access", "address": u32, "enabled": bool, "size"?: 1|2|4|8}`。`execute` 不得携带 `size`；`read`/`write`/`access` 必须携带 `size`，且 `address` 按 `size` 对齐。成功返回 HTTP 201 与 breakpoint 对象。
- `GET /v1/breakpoints`：返回按 id 升序的 breakpoint 对象数组；可用 `kind` 与 `enabled=true|false` 查询参数联合筛选。未知参数、重复参数或非法值返回 `invalid_query`（HTTP 400）。
- `PATCH /v1/breakpoints/{id}`：请求体只能为 `{"enabled": bool}`，返回更新后的对象。
- `DELETE /v1/breakpoints/{id}`：返回 HTTP 200 与 `{"deleted": id}`。

错误语义：请求体不是合法 JSON 对象返回 `invalid_request`；字段缺失、多余、类型错误、数值越界、execute 携带 size、观察点缺少 size 或地址未对齐返回 `invalid_field`（字段校验先于重复检查）；`kind`、`address`、`size` 相同的记录视为重复（与启用状态无关），返回 HTTP 409 `duplicate_breakpoint`；不存在的正整数 id 返回 HTTP 404 `breakpoint_not_found`；路径 id 不是十进制正整数返回 HTTP 400 `invalid_breakpoint_id`。

## 验证

```bash
PYTHONPATH=src python3 -m unittest discover -s tests -v
```

栈回溯等后续能力仍刻意未实现，以便后续任务从已冻结事实出发独立设计并验证这些能力。
