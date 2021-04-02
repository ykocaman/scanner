package utils

import (
	"io/ioutil"
	"log"
	"net/http"
	"time"

	"github.com/ykocaman/scanner/configs"
)

func GetContent(url string) string {
	client := http.Client{
		Timeout: time.Second * 10,
	}

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

	// people1 := {}
	// jsonErr := json.Unmarshal(body, &people1)
	// if jsonErr != nil {
	// 	log.Fatal(jsonErr)
	// }
}

func GetCVECodes() string {
	for _, cve := range configs.GetCVEs() {
		return GetContent(cve["url"])
	}
	return ""
}
