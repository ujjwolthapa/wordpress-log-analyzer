package cmd

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/spf13/cobra"
)

// file flag
var file string

// IPInfo holds geolocation information for an IP
type IPInfo struct {
	IP          string `json:"ip"`
	City        string `json:"city"`
	Region      string `json:"region"`
	Country     string `json:"country_name"`
	CountryCode string `json:"country_code"`
	Org         string `json:"org"`
	ASN         string `json:"asn"`
}

// getIPInfo fetches geolocation data for an IP using ip-api.com (free, no rate limit for non-commercial)
func getIPInfo(ip string) (*IPInfo, error) {
	// Skip private/local IPs
	if isPrivateIP(ip) {
		return &IPInfo{IP: ip, Org: "Private Network"}, nil
	}

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(fmt.Sprintf("http://ip-api.com/json/%s", ip))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var info IPInfo
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		return nil, err
	}
	return &info, nil
}

// getReverseDNS performs reverse DNS lookup for an IP
func getReverseDNS(ip string) string {
	names, err := net.LookupAddr(ip)
	if err != nil || len(names) == 0 {
		return "-"
	}
	hostname := strings.TrimSuffix(names[0], ".")
	return hostname
}

// isPrivateIP checks if an IP is private/local
func isPrivateIP(ip string) bool {
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return false
	}
	_, private24, _ := net.ParseCIDR("10.0.0.0/8")
	_, private20, _ := net.ParseCIDR("172.16.0.0/12")
	_, private16, _ := net.ParseCIDR("192.168.0.0/16")
	_, loopback, _ := net.ParseCIDR("127.0.0.0/8")

	return private24.Contains(parsedIP) ||
		private20.Contains(parsedIP) ||
		private16.Contains(parsedIP) ||
		loopback.Contains(parsedIP) ||
		parsedIP.IsLoopback() ||
		parsedIP.IsUnspecified()
}

// enrichIPs fetches geolocation and reverse DNS for top IPs concurrently
func enrichIPs(ips []string, maxConcurrent int) map[string]*IPInfo {
	results := make(map[string]*IPInfo)
	var wg sync.WaitGroup
	semaphore := make(chan struct{}, maxConcurrent)

	for _, ip := range ips {
		wg.Add(1)
		semaphore <- struct{}{}
		go func(ip string) {
			defer wg.Done()
			defer func() { <-semaphore }()

			// Reverse DNS
			hostname := getReverseDNS(ip)

			// Geolocation
			info, err := getIPInfo(ip)
			if err != nil {
				results[ip] = &IPInfo{IP: ip, Org: "Unknown", City: "Unknown"}
				return
			}
			info.Org = fmt.Sprintf("%s (%s)", info.Org, hostname)
			results[ip] = info
		}(ip)
	}

	wg.Wait()
	return results
}

// addReason adds a reason to the slice only if it doesn't already exist (avoids duplicates)
func addReason(reasons []string, reason string) []string {
	for _, r := range reasons {
		if r == reason {
			return reasons
		}
	}
	return append(reasons, reason)
}

// logsCmd analyzes access logs for attacks and patterns
var logsCmd = &cobra.Command{
	Use:   "logs",
	Short: "Analyze access logs for attacks and patterns",
	Run: func(cmd *cobra.Command, args []string) {
		// Open the log file
		f, err := os.Open(file)
		if err != nil {
			fmt.Println("Error opening file:", err)
			return
		}
		defer f.Close()

		// Initialize counters and maps OUTSIDE the loop
		ipCount := make(map[string]int)
		wpLoginAttempts := make(map[string]int)
		suspiciousIPs := make(map[string][]string) // Changed to store reasons
		var errorCount int

		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := scanner.Text()
			lower := strings.ToLower(line) // Define 'lower' once here

			// Split line into parts
			parts := strings.Split(line, " ")
			if len(parts) < 8 {
				continue // skip invalid lines
			}

			ip := parts[0]
			status := parts[len(parts)-4]
			request := strings.Join(parts[5:8], " ") // "GET /path HTTP/1.1"

			// Count IP occurrences
			ipCount[ip]++

			// Detect wp-login brute force
			if strings.Contains(request, "/wp-login.php") {
				wpLoginAttempts[ip]++
				if wpLoginAttempts[ip] > 20 {
					suspiciousIPs[ip] = addReason(suspiciousIPs[ip], fmt.Sprintf("wp-login brute force (%d attempts)", wpLoginAttempts[ip]))
				}
			}

			// Count errors (4xx and 5xx)
			if strings.HasPrefix(status, "4") || strings.HasPrefix(status, "5") {
				errorCount++
			}

			// Suspicious paths
			suspiciousPatterns := []string{".env", "../", "..\\", "phpmyadmin", "xmlrpc.php", "wp-config.php"}
			for _, pattern := range suspiciousPatterns {
				if strings.Contains(strings.ToLower(request), pattern) {
					suspiciousIPs[ip] = addReason(suspiciousIPs[ip], fmt.Sprintf("suspicious path: %s", pattern))
					break
				}
			}

			// Optional: detect SQL injection attempts
			if strings.Contains(lower, "union select") ||
				strings.Contains(lower, "' or 1=1") ||
				strings.Contains(lower, "' or '1'='1") ||
				strings.Contains(lower, "union all select") ||
				strings.Contains(lower, "information_schema") ||
				strings.Contains(lower, "sleep(") ||
				strings.Contains(lower, "benchmark(") ||
				strings.Contains(lower, "order by") {
				suspiciousIPs[ip] = addReason(suspiciousIPs[ip], "SQL Injection")
			}

			// Optional: detect path traversal / LFI
			if strings.Contains(request, "../") ||
				strings.Contains(lower, "/etc/passwd") ||
				strings.Contains(lower, "c:\\windows\\system32") ||
				strings.Contains(lower, "/proc/self/environ") ||
				strings.Contains(lower, "/var/log/apache2/access.log") ||
				strings.Contains(lower, "../../../../") {
				suspiciousIPs[ip] = addReason(suspiciousIPs[ip], "Path traversal/LFI")
			}

			// Optional: detect XSS attempts
			if strings.Contains(lower, "<script>") ||
				strings.Contains(lower, "%3cscript%3e") ||
				strings.Contains(lower, "onerror=") ||
				strings.Contains(lower, "javascript:") ||
				strings.Contains(lower, "alert(") ||
				strings.Contains(lower, "onmouseover=") ||
				strings.Contains(lower, "data:text/html") {
				suspiciousIPs[ip] = addReason(suspiciousIPs[ip], "XSS")
			}

			// Optional: detect Remote File Inclusion (RFI) attempts
			if (strings.Contains(lower, "http://") || strings.Contains(lower, "https://")) &&
				(strings.Contains(lower, "?file=") || strings.Contains(lower, "?page=") ||
					strings.Contains(lower, "?url=") || strings.Contains(lower, "?include=")) {
				suspiciousIPs[ip] = addReason(suspiciousIPs[ip], "RFI")
			}

			// Optional: detect RCE (Remote Code Execution) / Command Injection attempts
			if strings.Contains(lower, "cmd=") ||
				strings.Contains(lower, "exec=") ||
				strings.Contains(lower, "system=") ||
				strings.Contains(lower, "passthru(") ||
				strings.Contains(lower, "shell_exec(") ||
				strings.Contains(lower, "phpinfo()") ||
				strings.Contains(lower, "wget ") ||
				strings.Contains(lower, "curl ") {
				suspiciousIPs[ip] = addReason(suspiciousIPs[ip], "RCE/Command Injection")
			}

			// Optional: detect WordPress debug log access
			if strings.Contains(lower, "debug.log") {
				suspiciousIPs[ip] = addReason(suspiciousIPs[ip], "WordPress debug log access")
			}
        }

		// ---- SORT TOP IPS ----
		type kv struct {
			Key   string
			Value int
		}
		var sortedIPs []kv
		var sortedbruteforceIPs []kv

		for k, v := range ipCount {
			sortedIPs = append(sortedIPs, kv{k, v})
		}

		sort.Slice(sortedIPs, func(i, j int) bool {
			return sortedIPs[i].Value > sortedIPs[j].Value
		})

		// ---- ENRICH TOP IPS WITH GEOLOCATION ----
		fmt.Println("\n🌍 Fetching geolocation data for top IPs...")
		var topIPs []string
		for i, kv := range sortedIPs {
			if i >= 10 {
				break
			}
			topIPs = append(topIPs, kv.Key)
		}
		ipInfoMap := enrichIPs(topIPs, 5) // 5 concurrent requests

		// ---- OUTPUT ----
		fmt.Println("\n🔥 Top 10 IPs:")
		for i, kv := range sortedIPs {
			if i >= 10 {
				break
			}
			info := ipInfoMap[kv.Key]
			location := fmt.Sprintf("%s, %s", info.City, info.Country)
			if info.City == "Unknown" {
				location = info.Country
			}
			fmt.Printf("%s => %d requests | 📍 %s | 🏢 %s\n", kv.Key, kv.Value, location, info.Org)
		}

		// change map into slice format with struct kv
		for k, v := range wpLoginAttempts {
			sortedbruteforceIPs = append(sortedbruteforceIPs, kv{k, v})
		}
		// sort
		sort.Slice(sortedbruteforceIPs, func(i, j int) bool {
			return sortedbruteforceIPs[i].Value > sortedbruteforceIPs[j].Value
		})

		// Enrich brute force IPs
		var bruteIPs []string
		for i, kv := range sortedbruteforceIPs {
			if i >= 10 {
				break
			}
			bruteIPs = append(bruteIPs, kv.Key)
		}
		bruteIPInfoMap := enrichIPs(bruteIPs, 5)

		fmt.Println("\n🚨 wp-login brute force attempts:")
		for i, kv := range sortedbruteforceIPs {
			if i >= 10 {
				break
			}
			info := bruteIPInfoMap[kv.Key]
			location := fmt.Sprintf("%s, %s", info.City, info.Country)
			if info.City == "Unknown" {
				location = info.Country
			}
			fmt.Printf("%s => %d attempts | 📍 %s | 🏢 %s\n", kv.Key, kv.Value, location, info.Org)
		}

		fmt.Println("\n⚠️ Total errors (4xx/5xx):", errorCount)

		// Sort suspicious IPs by number of attack types
		type suspiciousEntry struct {
			IP      string
			Reasons []string
			Count   int
		}
		var sortedSuspicious []suspiciousEntry
		for ip, reasons := range suspiciousIPs {
			sortedSuspicious = append(sortedSuspicious, suspiciousEntry{ip, reasons, len(reasons)})
		}
		sort.Slice(sortedSuspicious, func(i, j int) bool {
			return sortedSuspicious[i].Count > sortedSuspicious[j].Count
		})

		fmt.Println("\n🕵️ Suspicious IPs:")
		for _, entry := range sortedSuspicious {
			fmt.Printf("%s => %s\n", entry.IP, strings.Join(entry.Reasons, ", "))
		}
	},
}

// init adds the command and its flags
func init() {
	rootCmd.AddCommand(logsCmd)

	logsCmd.Flags().StringVarP(&file, "file", "f", "", "Log file path")
	logsCmd.MarkFlagRequired("file")
}
