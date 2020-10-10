package main

import (
	"fmt"
	"strconv"
	"strings"
)

// Record corresponds one line in the file
type Record struct {
	site string
	name string
	pass string
	date int
}

// RecordToString converts a record to string
func RecordToString(r Record) string {
	return r.site + " " + r.name + " " + r.pass + strconv.Itoa(r.date)
}

// StringToRecord converts a line to a record
func StringToRecord(str string) (Record, error) {
	strs := strings.Fields(str)

	if len(strs) != 4 {
		r := Record{"", "", "", 0}
		return r, fmt.Errorf("one line doesn't have four fields. %s", str)
	}

	date, err := strconv.Atoi(strs[3])
	if err != nil {
		r := Record{"", "", "", 0}
		return r, fmt.Errorf("the forth field of the line(%s) is not a number", strs[3])
	}

	return Record{strs[0], strs[1], strs[2], date}, nil
}
