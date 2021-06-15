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
## 进阶配置

```shell
BIU_AK="API密钥"
BIU_HOST="biu地址"
BIU_PORTS="新建项目使用的端口范围"
TYC_COOKIE="查询icp时用到天眼查的Cookie"
```

## 使用
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

- 查询备案并添加到已有项目中
```shell
biu-cli -icp xx公司 -pid 项目ID
```


- 查询备案并创建项目
```shell
biu-cli -icp xx公司 -pnew 项目名称
```


 - 配合 https://opendata.rapid7.com/sonar.https/ 使用

```shell
https://stedolan.github.io/jq/download/ 安装jq
zgrep 'exmaple.com' 2021-04-19-1618794424-https_get_443.json.gz|jq -r '.ip'|biu-cli -pid 项目ID
zgrep 'BeiJing Baidu Netcom Science Technology' 2021-04-19-1618794424-https_get_443.json.gz|jq -r '.ip'|biu-cli -pid 项目ID
```

 - 配合 https://opendata.rapid7.com/sonar.fdns_v2/ 使用
```shell
zgrep '\.example.com"' 2021-01-30-1611965078-fdns_a.json.gz|jq -r '.name'|biu-cli -pid 项目ID
zgrep '\.example.com"' 2021-01-30-1611965078-fdns_a.json.gz|jq -r '.value'|biu-cli -pid 项目ID
```
