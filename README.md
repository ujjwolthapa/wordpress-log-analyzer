# WordPress Log Analyzer

**A Go CLI tool to analyze WordPress access logs for attacks, brute force attempts, and suspicious activity.**

---

## Features

- 🔥 Top IP request statistics  
- 🚨 Detect `/wp-login.php` brute force attempts  
- ⚠️ Count 4xx/5xx HTTP errors  
- 🕵️ Detect suspicious IPs and paths (`.env`, `../`, `phpmyadmin`)  
- 💀 Detect SQL injection patterns (`UNION SELECT`, `' OR 1=1`)  
- 📁 Detect path traversal attempts (`../`)  

---

## Installation

Requires **Go 1.21+**.

Install the latest version:

```bash
go install github.com/ujjwolthapa/wordpress-log-analyzer@latest
