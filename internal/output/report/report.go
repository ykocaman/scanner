// Package report renders scan findings for humans (console table, email).
package report

import (
	"fmt"

	"github.com/fatih/color"
	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/jedib0t/go-pretty/v6/text"

	"github.com/ykocaman/scanner/internal/models"
)

// PrintFinding writes a single vulnerability match to stdout.
func PrintFinding(f models.Finding) {
	fmt.Println(
		color.YellowString("Source: "), color.MagentaString(f.Source),
		color.YellowString("Code: "), color.MagentaString(f.Code),
		color.YellowString("Publication Date: "), color.MagentaString(f.PublicDate),
		color.YellowString("Severity: "), color.MagentaString(f.Severity),
	)
	fmt.Println(f.Description)
	fmt.Println(color.CyanString(f.URL))
}

// Tally counts findings by severity and affected package name.
func Tally(findings []models.Finding) map[string]map[string]int {
	tally := make(map[string]map[string]int)
	for _, f := range findings {
		if tally[f.Severity] == nil {
			tally[f.Severity] = make(map[string]int)
		}
		tally[f.Severity][f.Component.Name]++
	}
	return tally
}

// BuildTable renders a severity x package summary table from tally,
// returning the total number of findings it contains.
func BuildTable(tally map[string]map[string]int) (t table.Writer, total int) {
	t = table.NewWriter()
	t.SetStyle(table.StyleColoredBright)
	t.Style().Options.SeparateRows = true

	t.SetColumnConfigs([]table.ColumnConfig{
		{Number: 1, AutoMerge: true},
		{Number: 2, AutoMerge: true},
		{Number: 3, Align: text.AlignCenter, AlignFooter: text.AlignCenter, AlignHeader: text.AlignCenter},
	})
	t.AppendHeader(table.Row{"SEVERITY", "PACKAGE", "COUNT"})

	for severity, counts := range tally {
		label := severity
		if label == "" {
			label = "unknown"
		}
		for pkg, count := range counts {
			t.AppendRow(table.Row{text.Format.Apply(text.FormatTitle, label), pkg, count}, table.RowConfig{AutoMerge: true})
			total += count
		}
	}

	t.AppendFooter(table.Row{"", "TOTAL", total})
	t.SortBy([]table.SortBy{
		{Name: "SEVERITY", Mode: table.Asc},
		{Name: "COUNT", Mode: table.DscNumeric},
	})

	return t, total
}
