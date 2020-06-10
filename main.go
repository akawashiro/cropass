package main

import (
	"fmt"
	"io/ioutil"
	"os"
)

var cropassPassDir = ""

func show(site string) {
	fmt.Println("site = " + site)
	passFiles, err := ioutil.ReadDir(cropassPassDir)
	if err != nil {
		panic(err)
	}
	for _, file := range passFiles {
		fmt.Println(file.Name())
	}
}

func new(site string, user string) {
}

func add(site string, user string, pass string) {
}

func importPass() {
}

func main() {
	cropassPassDir = os.Getenv("CROPASS_PASS_DIR")
	if cropassPassDir == "" {
		fmt.Println("CROPASS_PASS_DIR is not setted.")
		os.Exit(0)
	}
	if len(os.Args) < 2 {
		fmt.Println("The length of input is too short.")
		os.Exit(0)
	}
	command := os.Args[1]
	if command == "show" {
		site := "None"
		if 3 <= len(os.Args) {
			site = os.Args[2]
		}
		show(site)
	}
}
