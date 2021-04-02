package parsers

import (
	"encoding/json"
	"regexp"
	"strings"

	"github.com/ykocaman/scanner/models"
)

func GetObjectFromCVE(content string) []models.RedhatCVE {
	var redHatCVE []models.RedhatCVE
	json.Unmarshal([]byte(content), &redHatCVE)

	for key, cve := range redHatCVE {
		redHatCVE[key].Description = strings.ReplaceAll(cve.Description, cve.Code+" ", "")
	}

	return redHatCVE
}

func GenerateMapFromCVE(cves []models.RedhatCVE) (list map[string]map[string]models.RedhatCVE) {

	list = make(map[string]map[string]models.RedhatCVE, 1000)

	re := regexp.MustCompile("-[0-9]+:.*")

	for _, cve := range cves {

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
