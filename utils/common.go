package utils

import (
	"encoding/json"
	"io/ioutil"
	"log"
	"net/http"
	"regexp"
	"time"

	"github.com/ykocaman/scanner/configs"
	"github.com/ykocaman/scanner/models"
)

func GenerateMapFromCVE(cves []models.RedhatCVE) map[string][]string {

	var list map[string][]string = make(map[string][]string, 1000)

	re := regexp.MustCompile("-[0-9]+:.*")

	for _, cve := range cves {

		for _, library := range cve.AffectedPackages {

			key := re.ReplaceAllString(library, "")

			list[key] = append(list[key], cve.Code)
		}
	}

	return list
}

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

func GetObjectFromCVE(content string) []models.RedhatCVE {
	var redHatCVE []models.RedhatCVE
	json.Unmarshal([]byte(content), &redHatCVE)
	return redHatCVE
}

func GetCVECodes() string {
	for _, cve := range configs.GetCVEs() {
		return GetContent(cve["url"])
	}
	return ""
}
