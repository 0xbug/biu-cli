## SKILL
```
npx skills add https://github.com/0xbug/biu-cli --skill biu-cli
```
## 构建
```shell
go mod download
go build -o biu-cli ./cmd/biu-cli
```

## 安装（从 GitHub）
```shell
go install github.com/0xbug/biu-cli/cmd/biu-cli@latest
```
默认会安装到 `$(go env GOPATH)/bin`，可执行文件名为 `biu-cli`。

## 初始化配置
访问个人中心->安全设置 生成新的API密钥

```shell
biu-cli -ak API密钥 -host biu地址(https://x.x.x.x)
```
## 进阶配置

```shell
BIU_AK="API密钥"
BIU_HOST="biu地址"
BIU_PORTS="新建项目使用的端口范围"
```

## 使用
 - JSON 输出
默认输出为表格/文本格式，添加 `-json` 后会输出结构化 JSON，便于脚本处理。
```shell
biu-cli -json
biu-cli -ip 1.1.1.1 -json
biu-cli -ip 1.1.1.1/24 -json
biu-cli -pid 项目ID -pv -json
biu-cli -pid 项目ID -pvul -json
cat ip.txt|biu-cli -s -json
```

 - 查询IP
```shell
biu-cli -ip 1.1.1.1
biu-cli -ip 1.1.1.1/24
```

 - 查询多个IP或域名
```shell
cat ip.txt|biu-cli -s
```
 - 进入查询模式
```shell
biu-cli -s
```
 - 查看已有项目
```shell
biu-cli
```
 - 创建项目
```shell
biu-cli -pnew 项目名称
```
 - 添加目标到已有项目中
```shell
cat ip.txt|biu-cli -pid 项目ID
cat domain.txt|biu-cli -pid 项目ID
```
 - 查看项目漏洞列表
```shell
biu-cli -pid 项目ID -pvul
biu-cli -pid 项目ID -pvul -json
biu-cli -pid 项目ID -pvul -l 50 -v
biu-cli -pid 项目ID -pvul -from 2
```
 - 查看漏洞详情
```shell
biu-cli -vmd5 漏洞md5
biu-cli -vmd5 漏洞md5 -json
```
 - 查看插件详情（漏洞标题）
```shell
biu-cli -plugin "Sentry 服务端请求伪造漏洞"
biu-cli -plugin "Sentry 服务端请求伪造漏洞" -json
```
