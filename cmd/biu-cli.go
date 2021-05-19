package main

import (
	"bufio"
	"crypto/tls"
	"flag"
	"fmt"
	"github.com/go-resty/resty/v2"
	"github.com/joho/godotenv"
	"github.com/olekukonko/tablewriter"
	"github.com/projectdiscovery/mapcidr"
	"github.com/tidwall/gjson"
	"log"
	"os"
	"strings"
)

var (
	isSearch bool
	biu      string
	ak       string
	pnew     string
	pid      string
	ip       string
	pageSize int
	client   = resty.New()
	version  = "v0.3"
)

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

func addTargetToProject(target string) {
	if target != "" {
		resp, err := biuClient().
			SetHeader("Content-Type", "application/json").
			SetBody(`{"asset": "` + target + `" }`).
			Patch(fmt.Sprintf("%s/api/project/optimize?project_id=%s", biu, pid))
		if err != nil {
			fmt.Print(err)
		}
		if resp.StatusCode() == 200 {
			fmt.Println(fmt.Sprintf("添加成功 %s", target))

		}
	}
}
func listProjects() {
	resp, err := biuClient().
		Get(fmt.Sprintf("%s/api/project?limit=%d&from=1&public=false", biu, pageSize))
	if err != nil {
		fmt.Print(err)
	}
	if resp.StatusCode() == 200 {
		fmt.Println(fmt.Sprintf("编号\t项目ID                            \t名称"))
		value := gjson.Get(string(resp.Body()), "result")
		for index, result := range value.Array() {
			fmt.Println(fmt.Sprintf("%d\t%s\t%s", index, result.Get("md5"), result.Get("name")))
		}

	}
}
func addProject() {
	resp, err := biuClient().
		SetHeader("Content-Type", "application/json").
		SetBody(`{"asset":"","name":"` + pnew + `","ports":"21-22,80,443,1433,2181,2409,3306,3389,5601,6379,8009,8080,8443,8888,9200,27017","public":false,"scan":true,"organizations":[],"include_subdomain":true,"include_ip":true,"include_history":true,"period":0,"tags":[],"cover":null}`).
		Post(fmt.Sprintf("%s/api/project", biu))
	if err != nil {
		fmt.Print(err)
	}
	if resp.StatusCode() == 200 {
		result := gjson.Get(string(resp.Body()), "result")
		msg := gjson.Get(string(resp.Body()), "msg").Value()
		fmt.Println(msg)
		fmt.Println(result.Get("project_id").Value())
	}
}

func searchIP(ipaddr string) {
	fmt.Println(ipaddr)
	resp, err := biuClient().
		Get(fmt.Sprintf("%s/api/asset/search?target=%s", biu, ipaddr))
	if err != nil {
		fmt.Print(err)
	}
	if resp.StatusCode() == 200 {
		result := gjson.Get(string(resp.Body()), "result")
		ports := result.Get("ports")
		tags := result.Get("tags")
		hosts := result.Get("hosts")
		vulnerabilities := result.Get("vulnerabilities")
		if len(tags.Array()) != 0 {
			for _, tag := range tags.Array() {
				fmt.Println(tag)
			}
		}
		header := []string{}
		rows := make([][]string, 0, 0)
		if len(ports.Array()) != 0 {
			header = []string{"端口", "ip", "服务", "域名", "标题", "指纹", "URL", "证书"}
			rows = make([][]string, 0, len(ports.Array()))
			for _, service := range ports.Array() {
				t := ""
				for _, tag := range service.Get("tags").Array() {
					if t != "" {
						t = fmt.Sprintf("%s,%s", t, tag.String())

					} else {
						t = fmt.Sprintf(tag.String())

					}
				}

				rows = append(rows, []string{service.Get("port").String(), service.Get("ip").String(), service.Get("service").Str, service.Get("tag").Str, service.Get("title").Str, t, service.Get("url").Str, service.Get("organization").Str})
			}
			biuPrint(header, rows)
		}

		if len(vulnerabilities.Array()) != 0 {
			header = []string{"风险等级", "插件", "目标"}
			rows = make([][]string, 0, len(vulnerabilities.Array()))
			for _, vulnerability := range vulnerabilities.Array() {
				rows = append(rows, []string{vulnerability.Get("severity").Str, vulnerability.Get("plugin").Str, vulnerability.Get("target").Str})
			}
			biuPrint(header, rows)
		}
		if len(hosts.Array()) != 0 {
			header = []string{"根域名", "域名", "ip", "标题", "指纹", "URL"}
			rows = make([][]string, 0, len(hosts.Array()))
			for _, host := range hosts.Array() {
				t := ""
				for _, tag := range host.Get("tags").Array() {
					if t != "" {
						t = fmt.Sprintf("%s,%s", t, tag.String())

					} else {
						t = fmt.Sprintf(tag.String())

					}
				}
				rows = append(rows, []string{host.Get("domain").Str, host.Get("host").Str, host.Get("ip").String(), host.Get("title").Str, t, host.Get("url").Str})
			}
			biuPrint(header, rows)
		}
		fmt.Println("------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------")
	}
}

func initEnv() {
	homeDir, _ := os.UserHomeDir()
	envPath := fmt.Sprintf("%s/.biu.env", homeDir)
	err := godotenv.Load(fmt.Sprintf(envPath))
	if err != nil {
		if ak != "" && biu != "" {
			var DefaultServerOptions = map[string]string{
				"BIU_AK":   ak,
				"BIU_HOST": biu,
			}
			err := godotenv.Write(DefaultServerOptions, envPath)
			if err != nil {
				fmt.Println("配置初始化成功")
			}
		} else {
			log.Fatal("请初始化配置: biu-cli -ak xxx -host https://x.x.x.x")

		}
	} else {
		ak = os.Getenv("BIU_AK")
		biu = os.Getenv("BIU_HOST")

	}

}
func main() {
	client.SetTLSClientConfig(&tls.Config{InsecureSkipVerify: true})
	flag.StringVar(&ak, "ak", "", "biu api key")
	flag.StringVar(&biu, "host", "", "biu host url: https://x.x.x.x")
	flag.StringVar(&pnew, "pnew", "", "biu new project name")
	flag.StringVar(&pid, "pid", "", "biu project id")
	flag.StringVar(&ip, "ip", "", "biu search ip")
	flag.BoolVar(&isSearch, "s", false, "biu 搜索模式")
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
		flag.Parse()
		if pid == "" {
			if pnew == "" {
				listProjects()
			} else {
				addProject()
			}
		} else {
			scanner := bufio.NewScanner(os.Stdin)
			for scanner.Scan() {
				addTargetToProject(scanner.Text())
			}
		}
	}

}
