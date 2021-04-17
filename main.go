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
	list := dataParsers.GenerateMapFromCVE(redhatCVEs)
	components := systemParsers.GetComponents()

	affectedTotalCount := 0

	for _, component := range components {
		if len(list[component.Name]) > 0 {
			fmt.Println(color.BlueString("%s, %s (%s)", component.Name, component.Version, component.RawVersion))

			affectedCount := 0

			for _, cve := range list[component.Name] {
				for _, affected := range cve.AffectedPackages {
					if strings.Contains(affected, component.Version) {
						fmt.Println(
							color.YellowString("Code: "), color.MagentaString(cve.Code),
							color.YellowString("Publication Date: "), color.MagentaString(cve.PublicDate),
							color.YellowString("Severity: "), color.MagentaString(cve.Severity),
						)
						fmt.Println(cve.Description)
						fmt.Println(color.CyanString(cve.URL))
						fmt.Println(cve.AffectedPackages)
						affectedCount++
						affectedTotalCount++
						break
					}
				}

			}

			if affectedCount < 1 {
				fmt.Println(color.GreenString("None"))
			} else {
				fmt.Println(color.RedString("Count: %d ", affectedCount))
			}
		}
	}

	fmt.Println(color.RedString("Total: %d ", affectedTotalCount))

}
