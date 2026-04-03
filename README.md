# JA4Finger

`JA4Finger` 是一个 Rust 实现的 JA4 家族指纹工具，当前支持：

- `JA4T`：TCP client SYN 指纹
- `JA4`：TLS ClientHello 指纹
- `JA4H`：明文 `HTTP/1.x` 和明文 `h2c` 指纹

工具当前提供三个子命令：

- `pcap`：离线分析 PCAP 文件
- `daemon`：在 Linux 网卡上前台持续抓包
- `aggregate`：离线关联分析 `daemon` 日志或 `pcap` 文本输出

## 构建

```bash
cargo build
```

调试运行也可以直接使用：

```bash
cargo run -- --help
```

## 一键产出可分发的 musl 发布包

如果你要把二进制拷到其他 Linux 机器运行，优先使用 `musl` 发布包，而不是默认的 `glibc` 动态链接版本。

一键打包：

```bash
bash ./scripts/package-musl-release.sh
```

脚本会自动完成：

- 检查并安装 `x86_64-unknown-linux-musl` Rust target
- 构建 `release` 二进制
- 在 `dist/` 下生成可分发目录
- 生成 `.tar.gz` 压缩包
- 生成对应的 `sha256` 校验文件

默认产物路径示例：

```text
dist/ja4finger-v1.1.7-x86_64-unknown-linux-musl/
dist/ja4finger-v1.1.7-x86_64-unknown-linux-musl.tar.gz
dist/ja4finger-v1.1.7-x86_64-unknown-linux-musl.sha256
```

如果你要覆盖目标架构，可以用环境变量：

```bash
TARGET=x86_64-unknown-linux-musl bash ./scripts/package-musl-release.sh
```

## 命令行用法

总览：

```bash
ja4finger <COMMAND>
```

可用子命令：

```bash
ja4finger daemon --config <FILE>
ja4finger pcap --file <FILE>
ja4finger aggregate --file <FILE> --window-secs <SECONDS>
```

如果还没有安装到系统路径，可以直接用 `cargo run`：

```bash
cargo run -- daemon --config ./daemon.yaml
cargo run -- aggregate --file ./logs/20260403-ja4finger.log --window-secs 300
cargo run -- pcap --file ./sample.pcap
```

## 离线分析 PCAP

分析一个 PCAP 文件：

```bash
./target/debug/ja4finger pcap --file ./sample.pcap
```

常见输出包含两类：

1. 指纹输出
2. 运行摘要

示例：

```text
ts=1.000000 mode=pcap kind=ja4h value=ge11cr04enus_33f7519adbc8_6263fd0189b4_230379c57c15 src=192.168.1.10:42424 dst=192.168.1.20:80
mode=pcap packets_seen=1 flows_tracked=1 fingerprints_emitted=1 parse_failures=0 extraction_failures=0
```

字段说明：

- `ts`：包时间戳
- `mode`：运行模式，`pcap` 或 `daemon`
- `kind`：指纹类型，`ja4` / `ja4h` / `ja4t`
- `value`：指纹值
- `src` / `dst`：源和目标端点
- `packets_seen`：处理过的包数
- `flows_tracked`：当前跟踪到的流数
- `fingerprints_emitted`：成功输出的指纹数
- `parse_failures`：可恢复解析失败次数
- `extraction_failures`：特征提取失败次数

## 前台抓包模式

`daemon` 模式通过 YAML 文件加载监听网卡、源地址排除、目的地址排除和日志输出位置。

最小 `daemon.yaml` 示例：

```yaml
daemon:
  iface: eth0
  src_excludes: []
  dst_excludes: []
```

如果你需要显式配置日志目录和文件名，可以写成：

```yaml
daemon:
  iface: eth0
  src_excludes:
    - 127.0.0.1
    - 10.0.0.0/8
  dst_excludes:
    - 192.168.1.100
    - 172.16.0.0/12
  log_dir: logs
  log_file: ja4finger.log
```

运行示例：

```bash
./target/debug/ja4finger daemon --config ./daemon.yaml
```

说明：

- `daemon` 模式是前台长运行进程，适合交给 `systemd` 或其他 supervisor 管理
- 默认会在当前目录创建 `./logs/`，并将日志追加写入 `yyyyMMdd-ja4finger.log`
- 进程收到支持的终止信号后会尽量干净退出，并把最终摘要写入日志文件
- 如果网卡不存在或权限不足，进程会以非零状态退出

## 聚合分析模式

`aggregate` 模式用于离线分析 `daemon` 日志或 `pcap` 子命令输出的文本结果。

示例：

```bash
./target/debug/ja4finger aggregate --file ./logs/20260403-ja4finger.log --window-secs 300
```

输出规则：

- 只读取带有 `ts`、`kind`、`value`、`src`、`dst` 的指纹行
- 自动跳过 `status` 行和 summary 行
- 按完整 `src` + `dst` 端点聚合，包含端口
- 以每条 `ja4` 为锚点，在 `[ja4_ts, ja4_ts + window_secs)` 内查找同一 `src/dst` 的 `ja4h` 或 `ja4t`
- 只有存在 `ja4 + ja4h` 或 `ja4 + ja4t` 关联时才输出
- 相同锚点下的重复 `ja4h` / `ja4t` 值会去重，但不会把 `ja4h` 和 `ja4t` 压成同一条组合记录

示例输出：

```text
anchor_ts=10.000000 window_secs=300 src=192.168.1.10:42424 dst=192.168.1.20:443 ja4=ja4-alpha ja4h=ja4h-alpha ja4t=
anchor_ts=10.000000 window_secs=300 src=192.168.1.10:42424 dst=192.168.1.20:443 ja4=ja4-alpha ja4h= ja4t=ja4t-alpha
```

## 源码结构

当前 CLI 按子命令拆分到 `src/commands/`：

- `src/main.rs`：薄入口，只负责初始化日志、解析命令、分发子命令、统一退出码
- `src/cli.rs`：`clap` 命令定义
- `src/commands/daemon.rs`：`daemon` 子命令入口和 daemon 相关测试
- `src/commands/pcap.rs`：`pcap` 子命令入口和包处理流程
- `src/commands/aggregate.rs`：`aggregate` 子命令入口
- `src/aggregator.rs`：聚合分析的纯逻辑实现
- 其他模块如 `capture.rs`、`config.rs`、`fingerprint.rs`、`output.rs`、`pipeline.rs`、`runtime.rs` 继续负责抓包、配置、指纹提取、输出和运行时支持

## 支持边界

当前明确支持：

- `JA4T`
- `JA4`
- `JA4H` on cleartext `HTTP/1.x`
- `JA4H` on cleartext `h2c`

当前不支持：

- TLS 承载的 `h2`
- `HTTP/3`
- `QUIC`

## 开发验证

运行测试：

```bash
cargo test
```

检查格式：

```bash
cargo fmt --check
```
