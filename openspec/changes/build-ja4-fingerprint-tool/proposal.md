## Why

当前仓库还没有可用的 JA4 指纹分析程序，但需求已经明确要求同时支持在线监听指定网卡流量和离线分析 PCAP 文件。若首版同时承诺 HTTP 与 HTTPS 指纹，会在命名、规范对齐和验收上引入不必要的不确定性。现在将范围收敛为基于 TLS ClientHello 的 JA4 首版工具，可以先交付一个可运行、可验证、可试用的版本，并为后续补充 JA4H、TCP 指纹与性能优化建立稳定边界。

## What Changes

- 新增一个基于 Go 的 `ja4finger` 工具，支持 CLI 方式分析指定 PCAP 文件。
- 新增一个基于 Go 的 `ja4finger` 实时监听模式，支持持续监控指定网卡流量，并可由外部进程管理器后台托管。
- 新增统一的流量分析流水线，复用抓包、解析、指纹计算和输出逻辑，避免 live/pcap 两条实现分叉。
- 首版仅实现基于 TLS ClientHello 的 JA4 指纹识别与日志输出。
- 定义 TCP 指纹扩展接口，使后续新增 TCP 指纹能力时无需重构主流程。
- 输出至少包含源地址、源端口、协议类型、指纹类型与指纹值的日志记录。

## Capabilities

### New Capabilities
- `ja4-fingerprint-analysis`: 提供统一的 JA4 流量采集、TLS/HTTPS JA4 指纹提取、实时监听与离线 PCAP 分析能力。

### Modified Capabilities
- None.

## Impact

- Affected code: 新增 Go 项目结构、CLI 入口、抓包/PCAP 读取模块、协议解析模块、指纹计算模块与日志输出模块。
- APIs: 新增命令行接口，例如 `live` 与 `pcap` 子命令及其参数。
- Dependencies: 预计引入 Go 抓包与 TLS 解析相关依赖，例如 `gopacket/pcap` 或等效库。
- Systems: live 模式运行时依赖宿主机网卡访问权限与抓包能力；PCAP 模式依赖本地文件输入。
