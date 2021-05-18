package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"github.com/go-resty/resty/v2"
	"github.com/joho/godotenv"
	"github.com/tidwall/gjson"
	"golang.org/x/crypto/ssh/terminal"
	"io/ioutil"
	"log"
	"os"
	"strings"
)

var (
	biu      string
	ak       string
	pid      string
	pageSize int
	client   = resty.New()
)

func addTargetToProject(target string) {
	if target != "" {
		resp, err := client.R().
			SetHeader("Content-Type", "application/json").
			SetHeader("Biu-Api-Key", ak).
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
	resp, err := client.R().
		SetHeader("Biu-Api-Key", ak).
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
	flag.StringVar(&pid, "pid", "", "biu project id")
	flag.IntVar(&pageSize, "l", 20, "pageSize")
	flag.Parse()
	initEnv()
	if pid == "" {
		listProjects()
	} else {
		data := flag.Args()
		if !terminal.IsTerminal(0) {
			b, err := ioutil.ReadAll(os.Stdin)
			if err == nil {
				data = append(data, string(b))
			}
		}
		targets := strings.Split(strings.Join(data, " "), "\n")
		for _, target := range targets {
			addTargetToProject(target)
		}
	}

}
