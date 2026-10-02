# ProbePoint

这是一个面向嵌入式调试的嵌入式调试与探针工具链。长期目标是提供调试协议编解码、断点与观察点、单步与栈回溯、符号解析、内存与寄存器读写、跟踪缓冲和性能计数，把调试探针沉淀为可复用工具链。

仓库采用 Python，当前冻结基线只提供进程健康检查。后续能力必须通过独立题目逐步实现；每个题目都应定义可观察的公共行为、兼容边界和失败语义，不得依赖未公开内部 API。

## 启动

```bash
PYTHONPATH=src python3 -m probepoint.server --host 127.0.0.1 --port 8080
```

服务默认监听 `127.0.0.1:8080`，可通过 `PROBEPOINT_ADDR` 修改。`GET /healthz` 返回 JSON 健康状态。

## 调试协议帧（v1）

帧字段均为网络字节序（大端）：两字节魔数 `0x5050`、一字节版本号（固定为 1）、一字节 flags、四字节 sequence、两字节 opcode、两字节 payload 长度、payload（可为空，最多 4096 字节）、四字节 CRC-32/ISO-HDLC；CRC 覆盖版本号起至 payload 末尾的全部字节。

### `POST /v1/frames/encode`

请求包含 `flags`（uint8）、`sequence`（uint32）、`opcode`（uint16）和 `payload`（偶数位十六进制字符串，无前缀无分隔符，可为空）。成功返回 `{"frame": "<完整帧小写十六进制>"}`。

```bash
curl -s -X POST http://127.0.0.1:8080/v1/frames/encode \
  -H 'Content-Type: application/json' \
  -d '{"flags":1,"sequence":42,"opcode":7,"payload":"cafe"}'
# {"frame": "505001010000002a00070002cafe9087dbb3"}
```

### `POST /v1/frames/decode`

请求只包含 `frame`（完整帧的十六进制字符串）。成功返回 `version`、`flags`、`sequence`、`opcode` 与小写 `payload`。解码失败按固定优先级返回 HTTP 400 及 `error.code`：`truncated_frame`（短于最小帧或短于声明长度）、`bad_magic`、`unsupported_version`、`invalid_length`、`trailing_data`、`checksum_mismatch`。

请求体不是合法 JSON 或不是对象时为 `invalid_request`；字段缺失、多余、类型错误、数值越界或十六进制格式错误为 `invalid_field`。

## 验证

```bash
PYTHONPATH=src python3 -m unittest discover -s tests -v
```

当前已实现进程健康检查与调试协议 v1 帧编解码；断点管理、栈回溯等其余能力仍待后续任务从已冻结事实出发独立设计并验证。
