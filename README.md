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

线上数据包由 `0x24`（`$`）、线上载荷、`0x23`（`#`）和两位小写十六进制校验和组成；载荷内 `0x24`、`0x23`、`0x7d`、`0x2a` 改写为 `0x7d` 后跟原值异或 `0x20`，校验和为线上载荷字节和模 256。

- `POST /v1/rsp/encode`：请求体为 `{"payload": "<偶数位十六进制>"}`，载荷可为空、上限 4096 字节，成功返回 `{"packet": "<完整数据包小写十六进制>"}`。
- `POST /v1/rsp/decode-stream`：无状态的流解析。请求体为 `{"data": "<偶数位十六进制，解码后不超过 1048576 字节>", "eof": bool}`；调用方将上次返回的 `remainder` 与新数据拼接后再次提交。返回 `{"packets", "controls", "errors", "discarded", "remainder"}`：`packets` 每项只含起始 `0x24` 的字节 `offset` 与解转义后的小写 `payload`；候选外 `0x2b`、`0x2d` 生成 `type` 为 `ack`、`nack` 的 control；`errors` 每项只含 `offset` 与 `code`；三个数组均按 `offset` 升序。其余噪声与失败候选字节计入 `discarded`。

包内未转义 `0x24` 使旧候选记 `nested_start` 并从新位置重启；校验字符非法记 `invalid_checksum`，校验不符记 `checksum_mismatch`，解转义载荷超过 4096 字节记 `invalid_length`。包级错误使用 HTTP 200，不阻断后续包。`eof=false` 时，缺 `0x23`、校验字符不足两位或末尾只有 `0x7d` 的候选从起始 `0x24` 原样进入小写 `remainder`，不报错也不丢弃；`eof=true` 时记 `truncated_packet`，全部丢弃且 `remainder` 为空。空 `data` 返回三个空数组、`0` 和空字符串。

请求体不是合法 JSON 对象返回 `invalid_request`（HTTP 400）；字段缺失、多余、类型或十六进制错误、`eof` 非布尔值、`data` 超限返回 `invalid_field`（HTTP 400）。

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

单步与栈回溯等后续能力仍刻意未实现，以便后续任务从已冻结事实出发独立设计并验证这些能力。
