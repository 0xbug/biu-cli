package main

import (
	"bufio"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/url"
	"os"
	"strings"

	"github.com/go-resty/resty/v2"
	"github.com/joho/godotenv"
	"github.com/olekukonko/tablewriter"
	"github.com/projectdiscovery/mapcidr"
	"github.com/tidwall/gjson"
)

var (
	isSearch        bool
	isViewMode      bool
	isVulnListMode  bool
	portsRanges = "21-22,80,443,1433,2181,2409,3306,3389,5601,6379,8009,8080,8443,8888,9200,27017"
	biuHost     string
	ak          string
	pnew        string
	pid         string
	vulnMD5     string
	pluginName  string
	ip          string
	verbose     bool
	outputJSON  bool
	pageSize    int
	pageFrom    int
	client      = resty.New()
	version     = "v0.10"
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

func listProjectVulnerabilities() {
	url := fmt.Sprintf("%s/api/scan/report?limit=%d&from=%d&is_public=true&keyword=&project_id=%s", biuHost, pageSize, pageFrom, pid)
	if verbose {
		fmt.Println(url)
	}
	resp, err := biuClient().Get(url)
	if err != nil {
		fmt.Print(err)
		return
	}
	if resp.StatusCode() != 200 {
		fmt.Println(gjson.Get(string(resp.Body()), "msg").String())
		return
	}
	body := string(resp.Body())
	total := gjson.Get(body, "total").Int()
	result := gjson.Get(body, "result")
	if outputJSON {
		printJSON(map[string]interface{}{
			"total":  total,
			"from":   pageFrom,
			"limit":  pageSize,
			"result": result.Value(),
		})
		return
	}
	maxPage := int((total + int64(pageSize) - 1) / int64(pageSize))
	if maxPage == 0 {
		maxPage = 1
	}
	fmt.Printf("项目漏洞: 共 %d 条，第 %d/%d 页，本页 %d 条\n", total, pageFrom, maxPage, len(result.Array()))
	if pageFrom < maxPage {
		fmt.Printf("下一页: biu-cli -pid %s -pvul -from %d -l %d\n", pid, pageFrom+1, pageSize)
	}
	if len(result.Array()) == 0 {
		return
	}
	header := []string{"风险等级", "状态", "插件", "主机", "目标", "漏洞ID"}
	rows := make([][]string, 0, len(result.Array()))
	for _, item := range result.Array() {
		host := fmt.Sprintf("%s:%s", item.Get("host").Str, item.Get("port").String())
		rows = append(rows, []string{
			item.Get("severity").Str,
			item.Get("status").Str,
			item.Get("plugin").Str,
			host,
			item.Get("target").Str,
			item.Get("md5").Str,
		})
	}
	biuPrint(header, rows)
}

func viewVulnerabilityDetail() {
	url := fmt.Sprintf("%s/api/scan/report?md5=%s", biuHost, vulnMD5)
	if verbose {
		fmt.Println(url)
	}
	resp, err := biuClient().Get(url)
	if err != nil {
		fmt.Print(err)
		return
	}
	if resp.StatusCode() != 200 {
		fmt.Println(gjson.Get(string(resp.Body()), "msg").String())
		return
	}
	body := string(resp.Body())
	total := gjson.Get(body, "total").Int()
	result := gjson.Get(body, "result")
	if outputJSON {
		printJSON(map[string]interface{}{
			"total":  total,
			"result": result.Value(),
		})
		return
	}
	host := fmt.Sprintf("%s:%s", result.Get("host").Str, result.Get("port").String())
	fmt.Printf("漏洞ID: %s\n", result.Get("md5").Str)
	fmt.Printf("风险等级: %s\n", result.Get("severity").Str)
	fmt.Printf("状态: %s\n", result.Get("status").Str)
	fmt.Printf("插件: %s\n", result.Get("plugin").Str)
	fmt.Printf("主机: %s\n", host)
	fmt.Printf("目标: %s\n", result.Get("target").Str)
	if result.Get("is_public").Exists() {
		fmt.Printf("公网: %v\n", result.Get("is_public").Bool())
	}
	if output := result.Get("output").Str; output != "" {
		fmt.Println("验证输出:")
		fmt.Println(output)
	}
	if raw := result.Get("retest_raw_data").Str; raw != "" && result.Get("output").Str == "" {
		fmt.Println("复测数据:")
		fmt.Println(raw)
	}
}

func viewPluginDetail() {
	filters, err := json.Marshal(map[string]string{"name": pluginName})
	if err != nil {
		fmt.Print(err)
		return
	}
	params := url.Values{}
	params.Set("limit", "1")
	params.Set("from", "1")
	params.Set("filters", string(filters))
	reqURL := fmt.Sprintf("%s/api/plugin?%s", biuHost, params.Encode())
	if verbose {
		fmt.Println(reqURL)
	}
	resp, err := biuClient().Get(reqURL)
	if err != nil {
		fmt.Print(err)
		return
	}
	if resp.StatusCode() != 200 {
		fmt.Println(gjson.Get(string(resp.Body()), "msg").String())
		return
	}
	body := string(resp.Body())
	total := gjson.Get(body, "total").Int()
	result := gjson.Get(body, "result")
	if outputJSON {
		printJSON(map[string]interface{}{
			"msg":    gjson.Get(body, "msg").Value(),
			"total":  total,
			"result": result.Value(),
		})
		return
	}
	fmt.Println(gjson.Get(body, "msg").String())
	if len(result.Array()) == 0 {
		fmt.Println("未查询到插件")
		return
	}
	plugin := result.Array()[0]
	products := make([]string, 0, len(plugin.Get("product").Array()))
	for _, p := range plugin.Get("product").Array() {
		products = append(products, p.String())
	}
	fmt.Printf("名称: %s\n", plugin.Get("name").Str)
	fmt.Printf("插件ID: %s\n", plugin.Get("md5").Str)
	fmt.Printf("类型: %s\n", plugin.Get("vulType").Str)
	fmt.Printf("风险等级: %v\n", plugin.Get("severity").Value())
	fmt.Printf("影响资产数: %d\n", plugin.Get("impact_count").Int())
	if len(products) > 0 {
		fmt.Printf("产品: %s\n", strings.Join(products, ", "))
	}
	if desc := plugin.Get("description").Str; desc != "" {
		fmt.Println("描述:")
		fmt.Println(desc)
	}
	if impact := plugin.Get("impact").Str; impact != "" {
		fmt.Println("影响:")
		fmt.Println(impact)
	}
	if solution := plugin.Get("solution").Str; solution != "" {
		fmt.Println("修复建议:")
		fmt.Println(solution)
	}
	if refs := plugin.Get("references").Str; refs != "" {
		fmt.Printf("参考: %s\n", refs)
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
	flag.StringVar(&vulnMD5, "vmd5", "", "漏洞 ID（md5），查看漏洞详情")
	flag.StringVar(&pluginName, "plugin", "", "漏洞标题/插件名称，查看插件详情")
	flag.StringVar(&ip, "ip", "", "biu search ip")
	flag.BoolVar(&isSearch, "s", false, "biu 搜索模式")
	flag.BoolVar(&isViewMode, "pv", false, "查看项目资产配置")
	flag.BoolVar(&isVulnListMode, "pvul", false, "查看项目漏洞列表")
	flag.BoolVar(&verbose, "v", false, "输出更多信息")
	flag.BoolVar(&outputJSON, "json", false, "输出 json 格式")
	flag.IntVar(&pageSize, "l", 20, "pageSize")
	flag.IntVar(&pageFrom, "from", 1, "分页页码，从 1 开始")
	flag.Parse()
	if isVulnListMode && pid == "" {
		log.Fatal("查看项目漏洞列表需要指定 -pid")
	}
	if isVulnListMode && pageFrom < 1 {
		log.Fatal("-from 页码须大于等于 1")
	}
	if isViewMode && isVulnListMode {
		log.Fatal("不能同时使用 -pv 与 -pvul")
	}
	if vulnMD5 != "" && pluginName != "" {
		log.Fatal("不能同时使用 -vmd5 与 -plugin")
	}
	if vulnMD5 != "" && (isVulnListMode || isViewMode || ip != "" || isSearch || pnew != "") {
		log.Fatal("-vmd5 不能与其他查询/项目操作同时使用")
	}
	if pluginName != "" && (isVulnListMode || isViewMode || ip != "" || isSearch || pnew != "") {
		log.Fatal("-plugin 不能与其他查询/项目操作同时使用")
	}
	initEnv()
	if vulnMD5 != "" {
		viewVulnerabilityDetail()
		return
	}
	if pluginName != "" {
		viewPluginDetail()
		return
	}
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
			if isVulnListMode {
				listProjectVulnerabilities()
			} else if isViewMode {
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
