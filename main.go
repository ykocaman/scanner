package main

import (
	"fmt"

	parsers "github.com/ykocaman/scanner/parsers/system"
	"github.com/ykocaman/scanner/utils"
)

func main() {

	redhatCVEs := utils.GetObjectFromCVE(utils.GetCVECodes())
	// for _, cve := range redhatCVEs {
	// 	if len(cve.AffectedPackages) > 0 {
	// 		// fmt.Println(cve.Code, cve.AffectedPackages)
	// 	}
	// }

	list := utils.GenerateMapFromCVE(redhatCVEs)

	components := parsers.GetComponents()
	for _, component := range components {
		if len(list[component.Name]) > 0 {
			fmt.Println(component.Name, component.Version)
			fmt.Println(list[component.Name])
		}
	}

}
