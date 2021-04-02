package utils

import (
	"crypto/tls"
	"io/ioutil"
	"log"
	"net/http"
	"time"

	"github.com/ykocaman/scanner/configs"
)

func GetContent(url string) string {
	client := http.Client{
		Timeout: time.Second * 30,
	}

	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}

	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		log.Fatal(err)
	}

	res, getErr := client.Do(req)
	if getErr != nil {
		log.Fatal(getErr)
	}

	if res.Body != nil {
		defer res.Body.Close()
	}

	body, readErr := ioutil.ReadAll(res.Body)
	if readErr != nil {
		log.Fatal(readErr)
	}

	return string(body)
}

func GetCVECodes() string {
	for _, cve := range configs.GetCVEs() {
		return GetContent(cve["url"])
	}
	return ""
}
