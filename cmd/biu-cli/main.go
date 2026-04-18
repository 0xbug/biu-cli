package main

import (
	"bufio"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/go-resty/resty/v2"
	"github.com/joho/godotenv"
	"github.com/olekukonko/tablewriter"
	"github.com/projectdiscovery/mapcidr"
	"github.com/tidwall/gjson"
)

var (
	isSearch    bool
	isViewMode  bool
	portsRanges = "21-22,80,443,1433,2181,2409,3306,3389,5601,6379,8009,8080,8443,8888,9200,27017"
	biuHost     string
	ak          string
	pnew        string
	pid         string
	ip          string
	verbose     bool
	outputJSON  bool
	pageSize    int
	client      = resty.New()
	version     = "v0.7"
)

func printJSON(data interface{}) {
	body, err := json.Marshal(data)
	if err != nil {
		fmt.Print(err)
		return
	}
	fmt.Println(string(body))
}

func biuPrint(header []string, data [][]string) {

	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader(header)
	table.SetAutoWrapText(false)
	table.SetAutoFormatHeaders(true)
	table.SetCenterSeparator("")
	table.SetAlignment(tablewriter.ALIGN_LEFT)
	table.SetHeaderAlignment(tablewriter.ALIGN_LEFT)
	table.SetColumnSeparator("")
	table.SetRowSeparator("")
	table.SetHeaderLine(false)
	table.SetBorder(false)
	table.SetTablePadding("\t")
	table.SetNoWhiteSpace(true)
	table.AppendBulk(data)
	table.Render()
}

func biuClient() *resty.Request {

	return client.R().SetHeader("Biu-Api-Key", ak).SetHeader("User-Agent", fmt.Sprintf("biu-cli %s", version))

}

func joinTags(tags gjson.Result) string {
	parts := make([]string, 0, len(tags.Array()))
	for _, tag := range tags.Array() {
		parts = append(parts, tag.String())
	}
	return strings.Join(parts, ",")
}

func addTargetToProject(target string) {
	if target != "" {
		resp, err := biuClient().
			SetHeader("Content-Type", "application/json").
			SetBody(`{"asset": "` + target + `" }`).
			Patch(fmt.Sprintf("%s/api/project/optimize?project_id=%s", biuHost, pid))
		if err != nil {
			fmt.Print(err)
		}
		if resp.StatusCode() == 200 {
			fmt.Println(fmt.Sprintf("添加成功 %s", target))

		}
	}
}
func viewProjectAssets() {
	resp, err := biuClient().
		Get(fmt.Sprintf("%s/api/project?md5=%s", biuHost, pid))
	if err != nil {
		fmt.Print(err)
	}
	if resp.StatusCode() == 200 {
		assets := gjson.Get(string(resp.Body()), "result").Get("assets")
		if outputJSON {
			printJSON(assets.Value())
			return
		}
		for _, asset := range assets.Array() {
			fmt.Println(asset)
		}

	}
}
func listProjects() {
	resp, err := biuClient().
		Get(fmt.Sprintf("%s/api/project?limit=%d&from=1&public=false", biuHost, pageSize))
	if err != nil {
		fmt.Print(err)
	}
	if resp.StatusCode() == 200 {
		value := gjson.Get(string(resp.Body()), "result")
		if outputJSON {
			printJSON(value.Value())
			return
		}
		if verbose {
			fmt.Println(fmt.Sprintf("%s/project", biuHost))
		}
		fmt.Println(fmt.Sprintf("编号\t项目ID                            \t名称"))
		for index, result := range value.Array() {
			fmt.Println(fmt.Sprintf("%d\t%s\t%s", index, result.Get("md5"), result.Get("name")))
		}

	}
}
func addProject() {
	if pid == "" {
		resp, err := biuClient().
			SetHeader("Content-Type", "application/json").
			SetBody(`{"asset":"","name":"` + pnew + `","ports":"` + portsRanges + `","public":false,"scan":true,"organizations":[],"include_subdomain":true,"include_ip":true,"include_history":true,"period":0,"tags":[],"cover":null}`).
			Post(fmt.Sprintf("%s/api/project", biuHost))
		if err != nil {
			fmt.Print(err)
		}
		if resp.StatusCode() == 200 {
			result := gjson.Get(string(resp.Body()), "result")
			msg := gjson.Get(string(resp.Body()), "msg").Value()
			fmt.Println(msg)
			fmt.Println(result.Get("project_id").Value())
			pid = result.Get("project_id").Str
			if verbose {
				fmt.Println(fmt.Sprintf("%s/assets/port?project_id=%s", biuHost, pid))
			}
		}
	}
}

func searchIP(ipaddr string) {
	resp, err := biuClient().
		Get(fmt.Sprintf("%s/api/asset/search?target=%s", biuHost, ipaddr))
	if err != nil {
		fmt.Print(err)
	}
	if resp.StatusCode() == 200 {
		result := gjson.Get(string(resp.Body()), "result")
		if outputJSON {
			printJSON(map[string]interface{}{
				"target": ipaddr,
				"result": result.Value(),
			})
			return
		}

		ports := result.Get("ports")
		tags := result.Get("tags")
		hosts := result.Get("hosts")
		vulnerabilities := result.Get("vulnerabilities")
		fmt.Printf("目标: %s\n", ipaddr)
		if len(tags.Array()) != 0 {
			fmt.Printf("标签: %s\n", joinTags(tags))
		}
		fmt.Printf("统计: 端口 %d | 风险 %d | 域名 %d\n", len(ports.Array()), len(vulnerabilities.Array()), len(hosts.Array()))

		hasResult := false
		header := []string{}
		rows := make([][]string, 0, 0)
		if len(ports.Array()) != 0 {
			hasResult = true
			fmt.Println("端口服务:")
			header = []string{"端口", "ip", "服务", "域名", "标题", "指纹", "URL", "证书"}
			rows = make([][]string, 0, len(ports.Array()))
			for _, service := range ports.Array() {
				rows = append(rows, []string{service.Get("port").String(), service.Get("ip").String(), service.Get("service").Str, service.Get("tag").Str, service.Get("title").Str, joinTags(service.Get("tags")), service.Get("url").Str, service.Get("organization").Str})
			}
			biuPrint(header, rows)
		}

		if len(vulnerabilities.Array()) != 0 {
			hasResult = true
			fmt.Println("风险漏洞:")
			header = []string{"风险等级", "插件", "目标"}
			rows = make([][]string, 0, len(vulnerabilities.Array()))
			for _, vulnerability := range vulnerabilities.Array() {
				rows = append(rows, []string{vulnerability.Get("severity").Str, vulnerability.Get("plugin").Str, vulnerability.Get("target").Str})
			}
			biuPrint(header, rows)
		}
		if len(hosts.Array()) != 0 {
			hasResult = true
			fmt.Println("关联域名:")
			header = []string{"根域名", "域名", "ip", "标题", "指纹", "URL"}
			rows = make([][]string, 0, len(hosts.Array()))
			for _, host := range hosts.Array() {
				rows = append(rows, []string{host.Get("domain").Str, host.Get("host").Str, host.Get("ip").String(), host.Get("title").Str, joinTags(host.Get("tags")), host.Get("url").Str})
			}
			biuPrint(header, rows)
		}
		if !hasResult {
			fmt.Println("未查询到资产数据")
		}
		fmt.Println()
	}
}

func initEnv() {
	homeDir, _ := os.UserHomeDir()
	envPath := fmt.Sprintf("%s/.biu.env", homeDir)
	err := godotenv.Load(fmt.Sprintf(envPath))
	if err != nil {
		if ak != "" && biuHost != "" {
			var DefaultServerOptions = map[string]string{
				"BIU_AK":    ak,
				"BIU_HOST":  biuHost,
				"BIU_PORTS": portsRanges,
			}
			err := godotenv.Write(DefaultServerOptions, envPath)
			if err != nil {
				fmt.Println("配置初始化成功")
			}
		} else {
			log.Fatal(fmt.Sprintf("请初始化配置: biu-cli -ak xxx -host https://x.x.x.x \n文件路径: %s", envPath))

		}
	} else {
		ak = os.Getenv("BIU_AK")
		biuHost = os.Getenv("BIU_HOST")
		portsRanges = os.Getenv("BIU_PORTS")

	}

}
func main() {
	client.SetTLSClientConfig(&tls.Config{InsecureSkipVerify: true})
	flag.StringVar(&ak, "ak", "", "biu api key")
	flag.StringVar(&biuHost, "host", "", "biu host url: https://x.x.x.x")
	flag.StringVar(&pnew, "pnew", "", "biu new project name")
	flag.StringVar(&pid, "pid", "", "biu project id")
	flag.StringVar(&ip, "ip", "", "biu search ip")
	flag.BoolVar(&isSearch, "s", false, "biu 搜索模式")
	flag.BoolVar(&isViewMode, "pv", false, "查看项目资产配置")
	flag.BoolVar(&verbose, "v", false, "输出更多信息")
	flag.BoolVar(&outputJSON, "json", false, "输出 json 格式")
	flag.IntVar(&pageSize, "l", 20, "pageSize")
	flag.Parse()
	initEnv()
	if isSearch {
		scanner := bufio.NewScanner(os.Stdin)
		for scanner.Scan() {
			searchIP(scanner.Text())
		}
	} else if ip != "" {
		if !strings.Contains(ip, "/") {
			ip = fmt.Sprintf("%s/32", ip)
		}
		ips, _ := mapcidr.IPAddresses(ip)
		for _, addr := range ips {
			searchIP(addr)
		}

	} else {
		if pid == "" {
			if pnew == "" {
				listProjects()
			} else {
				addProject()
			}
		} else {
			if isViewMode {
				viewProjectAssets()
			} else {
				scanner := bufio.NewScanner(os.Stdin)
				for scanner.Scan() {
					addTargetToProject(scanner.Text())
				}
			}
		}
	}

}
