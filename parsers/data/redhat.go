package parsers

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/ykocaman/scanner/models"
)

const CACHE_FILE = "cache"

func GetObjectFromCVE(content string) []models.RedhatCVE {
	var redHatCVE []models.RedhatCVE
	json.Unmarshal([]byte(content), &redHatCVE)

	for key, cve := range redHatCVE {
		redHatCVE[key].Description = strings.ReplaceAll(cve.Description, cve.Code+" ", "")
		redHatCVE[key].URL = fmt.Sprintf("https://access.redhat.com/security/cve/%s", cve.Code)
	}

	return redHatCVE
}

func GenerateMapFromCVE(cves []models.RedhatCVE) (list map[string]map[string]models.RedhatCVE) {
	USE_CACHING, _ := strconv.ParseBool(os.Getenv("USE_CACHING"))

	list = make(map[string]map[string]models.RedhatCVE, len(cves))

	re := regexp.MustCompile("-[0-9]+:.*")

	var cache []byte
	var f *os.File

	if USE_CACHING {
		cache, _ = ioutil.ReadFile(CACHE_FILE)
		f, err := os.OpenFile(CACHE_FILE, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			log.Fatal(err)
		}
		defer f.Close()
	}

	for _, cve := range cves {
		if USE_CACHING {
			if strings.Contains(string(cache), cve.Code) {
				continue
			}

			fmt.Fprintln(f, cve.Code)
		}

		for _, library := range cve.AffectedPackages {

			key := re.ReplaceAllString(library, "")
			if list[key] == nil {
				list[key] = make(map[string]models.RedhatCVE, len(cve.AffectedPackages))
			}
			list[key][cve.Code] = cve
		}
	}

	return
}
