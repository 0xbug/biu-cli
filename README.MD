## 构建
```shell
go mod download
go build -o biu-cli cmd/biu-cli.go
```

## 初始化配置
访问个人中心->安全设置 生成新的API密钥

```shell
biu-cli -ak API密钥 -host biu地址(https://x.x.x.x)

```

## 使用
 - 查看已有项目
```shell
biu-cli
```
 - 添加目标到已有项目中
```shell
cat ip.txt|biu-cli -pid 项目ID
cat domain.txt|biu-cli -pid 项目ID
```
