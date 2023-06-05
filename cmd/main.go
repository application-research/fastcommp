package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"time"

	"github.com/application-research/fastcommp"
)

func main() {
	// Get the file name from the command-line arguments
	if len(os.Args) != 2 {
		fmt.Printf("Usage: %s <filename>\n", os.Args[0])
		return
	}
	fileName := os.Args[1]

	start := time.Now()
	data, err := ioutil.ReadFile(fileName)
	if err != nil {
		fmt.Println("Error reading file:", err)
		return
	}

	elapsed := time.Since(start)
	fmt.Printf("Elapsed file read time: %s\n", elapsed)

	fast := new(fastcommp.CommpWriter)
	start = time.Now()
	fast.Write(data)
	sum, err := fast.Sum()
	if err != nil {
		panic(err)
	}

	elapsed = time.Since(start)
	fmt.Printf("Elapsed commP time: %s\n", elapsed)
	fmt.Printf("commP: %s\n", sum.PieceCID.String())

	// Convert the sum results to a JSON string
	results, err := json.MarshalIndent(sum, "", "  ")
	if err != nil {
		panic(err)
	}
	fmt.Println(string(results))

}
