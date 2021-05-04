package main

import (
	"context"
	"fmt"
	"log"
	"net/smtp"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/jedib0t/go-pretty/v6/text"
	"github.com/joho/godotenv"
	"github.com/olivere/elastic/v7"
	"github.com/ykocaman/scanner/configs"
	"github.com/ykocaman/scanner/models"
	dataParsers "github.com/ykocaman/scanner/parsers/data"
	systemParsers "github.com/ykocaman/scanner/parsers/system"
	"github.com/ykocaman/scanner/utils"
)

func main() {
	godotenv.Load()

	redhatCVEs := dataParsers.GetObjectFromCVE(utils.GetCVECodes())
	list := dataParsers.GenerateMapFromCVE(redhatCVEs)
	components := systemParsers.GetComponents()

	pivotAffecteds := make(map[string]map[string]int, len(list))

	for _, component := range components {
		if len(list[component.Name]) > 0 {
			fmt.Println(color.BlueString("%s, %s (%s)", component.Name, component.Version, component.RawVersion))

			affectedCount := 0

			for _, cve := range list[component.Name] {
				for _, affected := range cve.AffectedPackages {
					if strings.Contains(affected, component.Version) {
						printDetail(cve)
						affectedCount++

						if pivotAffecteds[cve.Severity] == nil {
							pivotAffecteds[cve.Severity] = make(map[string]int)
						}
						pivotAffecteds[cve.Severity][component.Name]++

						if result, _ := strconv.ParseBool(os.Getenv("USE_ELASTIC")); result {
							insertToElastic(cve, component)
						}

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

	printTable(pivotAffecteds)
}

func printDetail(cve models.RedhatCVE) {
	fmt.Println(
		color.YellowString("Code: "), color.MagentaString(cve.Code),
		color.YellowString("Publication Date: "), color.MagentaString(cve.PublicDate),
		color.YellowString("Severity: "), color.MagentaString(cve.Severity),
	)
	fmt.Println(cve.Description)
	fmt.Println(color.CyanString(cve.URL))
	fmt.Println(cve.AffectedPackages)
}

func printTable(pivotAffecteds map[string]map[string]int) {

	t := table.NewWriter()
	t.SetStyle(table.StyleColoredBright)
	t.Style().Options.SeparateRows = true

	t.SetColumnConfigs([]table.ColumnConfig{
		{Number: 1, AutoMerge: true},
		{Number: 2, AutoMerge: true},
		{Number: 3, Align: text.AlignCenter, AlignFooter: text.AlignCenter, AlignHeader: text.AlignCenter},
	})

	t.AppendHeader(table.Row{"SEVERITY", "PACKAGE", "COUNT"})

	affectedTotalCount := 0

	for severity, detail := range pivotAffecteds {
		for component, count := range detail {
			t.AppendRow(table.Row{text.Format.Apply(text.FormatTitle, severity), component, count}, table.RowConfig{AutoMerge: true})
			affectedTotalCount += count
		}

	}

	if affectedTotalCount == 0 {
		fmt.Println(color.GreenString("No new vulnerabilities detected!"))
		return
	}

	t.AppendFooter(table.Row{"", "TOTAL", affectedTotalCount})

	t.SortBy([]table.SortBy{
		{Name: "SEVERITY", Mode: table.Asc},
		{Name: "COUNT", Mode: table.DscNumeric},
	})

	fmt.Println()
	fmt.Println(t.Render())

	if result, _ := strconv.ParseBool(os.Getenv("SEND_MAIL")); result {
		sendEmail(t.RenderHTML(), strconv.Itoa(affectedTotalCount))
	}

	os.Exit(1)
}

func sendEmail(body, affectedTotalCount string) {
	from := os.Getenv("MAIL_USERNAME")
	pass := os.Getenv("MAIL_PASSWORD")
	to := os.Getenv("MAIL_TO")

	msg := "From: " + from + "\n" +
		"To: " + to + "\n" +
		"Subject: Vulnerability Report [" + affectedTotalCount + "]\n" +
		"MIME-version: 1.0;\nContent-Type: text/html; charset=\"UTF-8\";\n\n" +
		`<style>
			table {border-collapse: collapse;}
			td {padding: 10px;border: 1px solid black}
			th {padding: 10px;border: 1px solid black}
			tfoot {font-weight: bold; color: red}
		</style>` + "\n" +
		body

	err := smtp.SendMail(fmt.Sprintf("%s:%s", os.Getenv("MAIL_SERVER_HOST"), os.Getenv("MAIL_SERVER_PORT")),
		smtp.PlainAuth("", from, pass, os.Getenv("MAIL_SERVER_HOST")),
		from, []string{to}, []byte(msg))

	if err != nil {
		log.Printf("smtp error: %s", err)
		return
	}
}

func insertToElastic(cve models.RedhatCVE, component models.Component) {
	ctx := context.Background()

	client, err := elastic.NewClient(elastic.SetURL(os.Getenv("ELASTIC_HOST")))
	if err != nil {
		panic(err)
	}

	client.Index().
		Index(configs.ELASTIC_INDEX).
		BodyJson(
			struct {
				Code, Severity, AffectedPackage, AffectedVersion, URL, Description, Score, PublicDate, DetectionDate string
			}{
				Code:            cve.Code,
				Severity:        cve.Severity,
				PublicDate:      cve.PublicDate,
				DetectionDate:   time.Now().String(),
				URL:             cve.URL,
				Description:     cve.Description,
				Score:           cve.Score,
				AffectedPackage: component.Name,
				AffectedVersion: component.Version,
			}).
		Do(ctx)
	if err != nil {
		panic(err)
	}
}
