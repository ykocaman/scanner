package parsers

import (
	"log"
	"os/exec"
	"regexp"
	"strings"

	"github.com/ykocaman/scanner/models"
)

func GetComponents() (components []models.Component) {

	re := regexp.MustCompile(`(\d+\.)(\d+\.)(\d)|(\d+\.)(\d)|(\d)+\d`)

	out, err := exec.Command("apt", "list", "--installed").Output()
	if err != nil {
		log.Fatal(err)
	}
	var lines = strings.Split(string(out), "\n")
	lines = lines[1 : len(lines)-1]

	for _, line := range lines {
		properties := strings.Split(line, " ")
		identity := strings.Split(properties[0], "/")

		version := re.FindString(properties[1])

		components = append(components, models.Component{
			Name:       identity[0],
			Repo:       identity[1],
			Version:    version,
			RawVersion: properties[1],
			Arch:       properties[2],
			// Status:  properties[3],
		})
		// fmt.Printf("%s %s\n", name, version)
	}
	return
}
