package main

import (
	"fmt"
	"strings"

	"github.com/fatih/color"
	dataParsers "github.com/ykocaman/scanner/parsers/data"
	systemParsers "github.com/ykocaman/scanner/parsers/system"
	"github.com/ykocaman/scanner/utils"
)

func main() {

	redhatCVEs := dataParsers.GetObjectFromCVE(utils.GetCVECodes())
	// for _, cve := range redhatCVEs {
	// 	if len(cve.AffectedPackages) > 0 {
	// 		// fmt.Println(cve.Code, cve.AffectedPackages)
	// 	}
	// }

	list := dataParsers.GenerateMapFromCVE(redhatCVEs)

	components := systemParsers.GetComponents()
	for _, component := range components {
		if len(list[component.Name]) > 0 {
			fmt.Println(color.BlueString("%s, %s (%s)", component.Name, component.Version, component.RawVersion))

			affectedCount := 0

			for _, cve := range list[component.Name] {
				for _, affected := range cve.AffectedPackages {
					if strings.Contains(affected, component.Version) {
						fmt.Println(color.YellowString("Code: %s Publication Date: %s", cve.Code, cve.PublicDate))
						fmt.Println(cve.Description)
						fmt.Println(color.CyanString(cve.URL))
						fmt.Println(cve.AffectedPackages)
						affectedCount++
						break
					}
				}

			}

			if affectedCount < 1 {
				fmt.Println(color.GreenString("Zafiyet bulunamadi"))
			} else {
				fmt.Println(color.RedString("Toplam %d adet zafiyet bulundu", affectedCount))
			}
		}
	}

}
