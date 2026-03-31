package cmd

import (
	"bufio"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/spf13/cobra"
)

// file flag
var file string

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
		suspiciousIPs := make(map[string]bool)
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
					suspiciousIPs[ip] = true
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
					suspiciousIPs[ip] = true
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
				fmt.Println("💀 SQL Injection attempt from:", ip)
				suspiciousIPs[ip] = true
			}

			// Optional: detect path traversal / LFI
			if strings.Contains(request, "../") ||
				strings.Contains(lower, "/etc/passwd") ||
				strings.Contains(lower, "c:\\windows\\system32") ||
				strings.Contains(lower, "/proc/self/environ") ||
				strings.Contains(lower, "/var/log/apache2/access.log") ||
				strings.Contains(lower, "../../../../") { // Deeper traversal
				fmt.Println("📁 Path traversal/LFI attempt from:", ip)
				suspiciousIPs[ip] = true
			}

			// Optional: detect XSS attempts
			if strings.Contains(lower, "<script>") ||
				strings.Contains(lower, "%3cscript%3e") || // URL encoded
				strings.Contains(lower, "onerror=") ||
				strings.Contains(lower, "javascript:") ||
				strings.Contains(lower, "alert(") ||
				strings.Contains(lower, "onmouseover=") ||
				strings.Contains(lower, "data:text/html") {
				fmt.Println("💉 XSS attempt from:", ip)
				suspiciousIPs[ip] = true
			}

			// Optional: detect Remote File Inclusion (RFI) attempts
			if (strings.Contains(lower, "http://") || strings.Contains(lower, "https://")) &&
				(strings.Contains(lower, "?file=") || strings.Contains(lower, "?page=") ||
					strings.Contains(lower, "?url=") || strings.Contains(lower, "?include=")) {
				fmt.Println("☁️ RFI attempt from:", ip)
				suspiciousIPs[ip] = true
			}

			// Optional: detect RCE (Remote Code Execution) / Command Injection attempts
			if strings.Contains(lower, "cmd=") ||
				strings.Contains(lower, "exec=") ||
				strings.Contains(lower, "system=") ||
				strings.Contains(lower, "passthru(") ||
				strings.Contains(lower, "shell_exec(") ||
				strings.Contains(lower, "phpinfo()") ||
				strings.Contains(lower, "wget ") ||
				strings.Contains(lower, "curl ") ||
				strings.Contains(lower, ";") || // Command separator
				strings.Contains(lower, "|") || // Pipe
				strings.Contains(lower, "&&") { // Logical AND
				fmt.Println("💻 RCE/Command Injection attempt from:", ip)
				suspiciousIPs[ip] = true
			}

			// Optional: detect WordPress debug log access
			if strings.Contains(lower, "debug.log") {
				fmt.Println("🐛 WordPress debug log access attempt from:", ip)
				suspiciousIPs[ip] = true
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

		// ---- OUTPUT ----
		fmt.Println("\n🔥 Top 10 IPs:")
		for i, kv := range sortedIPs {
			if i >= 10 {
				break
			}
			fmt.Printf("%s => %d requests\n", kv.Key, kv.Value)
		}

		// change map into slice format with struct kv
		for k, v := range wpLoginAttempts {
			sortedbruteforceIPs = append(sortedbruteforceIPs, kv{k, v})
		}
		// sort
		sort.Slice(sortedbruteforceIPs, func(i, j int) bool {
			return sortedbruteforceIPs[i].Value > sortedbruteforceIPs[j].Value
		})

		fmt.Println("\n🚨 wp-login brute force attempts:")
		for i, kv := range sortedbruteforceIPs {
			if i >= 10 {
				break
			}
			fmt.Printf("%s => %d attempts\n", kv.Key, kv.Value)

		}

		fmt.Println("\n⚠️ Total errors (4xx/5xx):", errorCount)

		fmt.Println("\n🕵️ Suspicious IPs:")
		for ip := range suspiciousIPs {
			fmt.Println(ip)
		}
	},
}

// init adds the command and its flags
func init() {
	rootCmd.AddCommand(logsCmd)

	logsCmd.Flags().StringVarP(&file, "file", "f", "", "Log file path")
	logsCmd.MarkFlagRequired("file")
}
