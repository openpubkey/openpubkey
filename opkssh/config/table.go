package config

import "strings"

type Table struct {
	rows [][]string
}

func ToTable(content []byte) *Table {
	table := [][]string{}
	rows := strings.Split(string(content), "\n")
	for _, row := range rows {
		row := CleanRow(row)
		if row == "" {
			continue
		}
		columns := strings.Fields(row)
		table = append(table, columns)
	}
	return &Table{rows: table}
}

func CleanRow(row string) string {
	// Remove comments
	rowFixed := strings.Split(row, "#")[0]
	// Skip empty rows
	rowFixed = strings.TrimSpace(rowFixed)
	return rowFixed
}

func (t *Table) AddRow(row ...string) {
	t.rows = append(t.rows, row)
}

func (t Table) ToString() string {
	var sb strings.Builder
	for _, row := range t.rows {
		sb.WriteString(strings.Join(row, " ") + "\n")
	}
	return sb.String()
}

func (t Table) ToBytes() []byte {
	return []byte(t.ToString())
}

func (t Table) GetRows() [][]string {
	return t.rows
}
