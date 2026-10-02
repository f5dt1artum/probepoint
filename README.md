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

请求体非法返回 `error.code=invalid_request`；字段缺失、多余、类型或取值错误返回 `invalid_field`；帧解码失败按优先级返回 `truncated_frame`、`bad_magic`、`unsupported_version`、`invalid_length`、`trailing_data`、`checksum_mismatch`，均为 HTTP 400。

## 断点与观察点（v1）

记录仅保存在当前服务进程中，重启后为空，不产生任何持久化副作用。id 为按创建顺序递增的正整数，同一进程内删除后也不复用。

- `POST /v1/breakpoints`：请求体为 `{"kind": "execute|read|write|access", "address": u32, "enabled": bool, "size"?: 1|2|4|8}`。`execute` 不得携带 `size`（响应中为 `null`）；其余类型必须携带 `size`，且 `address` 按 `size` 对齐。成功返回 HTTP 201 和包含全部规范化字段（含 `id`）的对象。
- `GET /v1/breakpoints`：返回按 `id` 升序的记录数组，可用 `kind`、`enabled=true|false` 查询参数联合筛选。
- `PATCH /v1/breakpoints/{id}`：请求体只能是 `{"enabled": bool}`，返回更新后的对象。
- `DELETE /v1/breakpoints/{id}`：删除记录，返回 `{"deleted": id}`。

错误码：请求体不是合法 JSON 对象返回 `invalid_request`（HTTP 400）；字段缺失、多余、类型错误、数值越界、`execute` 携带 `size`、观察点缺少 `size` 或地址未对齐返回 `invalid_field`（HTTP 400，且字段校验先于重复检查）；`kind/address/size` 相同的记录重复创建（与 `enabled` 无关）返回 `duplicate_breakpoint`（HTTP 409）；查询参数未知、重复或取值非法返回 `invalid_query`（HTTP 400）；路径 id 不是十进制正整数返回 `invalid_breakpoint_id`（HTTP 400）；不存在的正整数 id 返回 `breakpoint_not_found`（HTTP 404）。

## 验证

```bash
PYTHONPATH=src python3 -m unittest discover -s tests -v
```

当前基线刻意不包含调试协议编解码、断点管理与栈回溯的实现，以便后续任务从已冻结事实出发独立设计并验证这些能力。
