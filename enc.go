package main

import (
	"fmt"
	"flag"
)

var filename string

func init() {
	flag.StringVar(&filename, "in", "", "file to be encrypted")
	flag.Parse()
}

func main() {
	fmt.Printf("input: %s\n", filename)
}