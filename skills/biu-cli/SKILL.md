---
name: biu-cli
description: >-
  biuasm 攻击面梳理平台biu-cli使用指南
---

# biu-cli

## 何时使用

用户在使用 **biu-cli**（连接 Biu 服务做资产查询、项目管理、批量加目标）时，按本文档执行biu-cli；

## 安装

远程安装：`go install github.com/0xbug/biu-cli/cmd/biu-cli@latest`（模块 `github.com/0xbug/biu-cli`），默认可执行文件名为 `biu-cli`。

## 首次认证与配置

1. 在 Biu **个人中心 → 安全设置** https://asm.biu.life/account/setting?tab=security 生成 API 密钥。
2. 首次初始化（将写入 `~/.biu.env`）：

```shell
biu-cli -ak API密钥 -host biu地址(https://x.x.x.x)
```

```shell
BIU_AK="API密钥"
BIU_HOST="biu地址"
BIU_PORTS="新建项目使用的端口范围"
```

- **`BIU_PORTS`**：新建项目（`-pnew`）时提交的默认端口范围字符串；与 CLI 内置默认端口列表一致时可不设置。
- 配置文件路径：**`~/.biu.env`**。

## 命令行选项速查

| Flag | 作用 |
|------|------|
| `-ak` | API 密钥；与 `-host` 一起用于首次写入配置 |
| `-host` | Biu 服务根 URL，例如 `https://x.x.x.x` |
| `-json` | 输出 JSON，便于脚本解析（列表/查询/查看项目资产等支持处会生效） |
| `-ip` | 查询目标：单个 IP 或 CIDR；非 CIDR 形式会在代码中按 `/32` 处理并用 mapcidr 展开 |
| `-s` | 搜索模式：从 **stdin** 按行读取 IP/域名并查询；无管道时等价交互式多行输入 |
| `-pnew` | 新建项目名称（无 `-pid` 时走创建项目逻辑） |
| `-pid` | 项目 ID；与 `-pv` 组合为查看该项目资产；与 `-pvul` 组合为查看该项目漏洞列表；否则从 stdin 每行读入一个目标并加入该项目 |
| `-pv` | 查看指定 `-pid` 的项目资产配置 |
| `-pvul` | 查看指定 `-pid` 的项目漏洞列表（调用 `/api/scan/report`） |
| `-vmd5` | 漏洞 ID（md5），查看单条漏洞详情（`GET /api/scan/report?md5=`） |
| `-plugin` | 漏洞标题/插件名称，查看插件详情（`GET /api/plugin?filters={"name":"..."}`） |
| `-v` | 更详细的辅助输出 |
| `-l` | 列出项目 / 漏洞列表时的分页大小（`limit`），默认 `20` |
| `-from` | 漏洞列表页码（`from`），从 `1` 开始，默认 `1` |

**主流程简述**：未指定 `-ip` 且未指定 `-s` 时，若既无 `-pnew` 也无 `-pid`，则执行 **列出已有项目**；`-pid` + `-pvul` 查看漏洞列表；`-pid` + `-pv` 查看资产；`-pid` 且无 `-pv` / `-pvul` 时从 stdin 读行添加目标（宜配合管道）。`-pv` 与 `-pvul` 不可同时使用。

请求头：HTTP 客户端会带 **`Biu-Api-Key`**（值为 `BIU_AK`）。

## 典型用法

### JSON 输出

默认表格/文本；加 `-json` 得到结构化 JSON。

```shell
biu-cli -json
biu-cli -ip 1.1.1.1 -json
biu-cli -ip 1.1.1.1/24 -json
biu-cli -pid 项目ID -pv -json
biu-cli -pid 项目ID -pvul -json
cat ip.txt|biu-cli -s -json
```

### 查询 IP / 网段

```shell
biu-cli -ip 1.1.1.1
biu-cli -ip 1.1.1.1/24
```

### 批量查询（管道或交互）

```shell
cat ip.txt|biu-cli -s
biu-cli -s
```

### 查看已有项目

```shell
biu-cli
```

### 创建项目

```shell
biu-cli -pnew 项目名称
```

### 向已有项目添加目标

```shell
cat ip.txt|biu-cli -pid 项目ID
cat domain.txt|biu-cli -pid 项目ID
```

### 查看项目漏洞列表

```shell
biu-cli -pid 项目ID -pvul
biu-cli -pid 项目ID -pvul -json
biu-cli -pid 项目ID -pvul -l 50 -v
biu-cli -pid 项目ID -pvul -from 2
```

### 查看漏洞详情

列表输出含「漏洞ID」列，或从平台复制 md5 后：

```shell
biu-cli -vmd5 99701eb2924f27664559946bcf627874
biu-cli -vmd5 99701eb2924f27664559946bcf627874 -json
biu-cli -vmd5 99701eb2924f27664559946bcf627874 -v
```

### 查看插件详情（按漏洞标题）

漏洞列表「插件」列或详情中的 `plugin` 字段即为插件名称：

```shell
biu-cli -plugin "Sentry 服务端请求伪造漏洞"
biu-cli -plugin "Sentry 服务端请求伪造漏洞" -json
```

## 代理提示

- 用户报错联不通或 401/403 时：优先核对 **`~/.biu.env`** 中的 **`BIU_AK`**、**`BIU_HOST`** 及网络可达性。
- **不要**要求用户「启动 biu-cli 验证应用是否能正常跑起来」作为常规排错步骤（除非用户明确要求）。
