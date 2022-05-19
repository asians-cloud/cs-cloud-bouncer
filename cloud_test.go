package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"strings"
)

const (
	binaryPath       = "./tests/custombinary"
	binaryOutputFile = "./data.txt"
)

var (
	durationWithUnit  = "1200s"
	durationInSeconds = durationWithUnit[:len(durationWithUnit)-1]
	sceanario         = "crowdsec/bruteforce"
	ip1               = "1.2.3.4"
	ip2               = "1.2.3.5"
	decisionType      = "IP"
)

type parsedLine struct {
	action    string
	value     string
	duration  string
	sceanario string
}

func parseFile(path string) []parsedLine {
	dat, err := ioutil.ReadFile(binaryOutputFile)
	parsedLines := make([]parsedLine, 0)
	if err != nil {
		panic(err)
	}
	for _, line := range strings.Split(string(dat), "\n") {
		if len(line) == 0 {
			continue
		}

		parsedLines = append(parsedLines, parseLine(line))
	}
	return parsedLines
}

func parseLine(line string) parsedLine {
	words := strings.Split(line, " ")
	return parsedLine{
		action:    words[0],
		value:     words[1],
		duration:  words[2],
		sceanario: words[3],
	}
}

func cleanup() {
	if _, err := os.Stat(binaryOutputFile); err != nil {
		fmt.Println("didnt found the file")
		return
	}
	os.Remove(binaryOutputFile)
}
