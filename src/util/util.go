package util

import (
	"bufio"
	"os"
	"strings"
	"unicode"
)

func GetHostnameAndIp() ([]string, []string, error) {
	var ipList []string
	var domainList []string

	hostsFile := "/etc/hosts"
	if _, err := os.Stat(hostsFile); os.IsNotExist(err) {
		// if null, return empty, no problem (windows?!)
		return ipList, domainList, nil
	}

	file, err := os.Open(hostsFile)
	if err != nil {
		return ipList, domainList, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)

	containerIp := ""

	// parse first line: containerIp,  containerId
	for scanner.Scan() {
		lineText := scanner.Text()
		if strings.HasPrefix(lineText, "#") == true {
			continue
		}
		f := func(c rune) bool {
			return unicode.IsSpace(c)
		}

		line := strings.FieldsFunc(lineText, f)
		ip := line[0]
		name := line[1]
		if containerIp == "" {
			containerIp = ip
			ipList = append(ipList, containerIp)
		}
		if containerIp == ip {
			domainList = append(domainList, name)
		}
	}
	return ipList, domainList, nil
}

func ListToString(array []string, s string) *string {
	result := ""

	for _, val := range array {
		result += val
		result += ","
	}
	if len(s) > 0 && s != "-" {
		result += s
		result += ","
	}

	res := ""
	if len(result) > 0 {
		res = result[:len(result)-1]
	}
	return &res

}
