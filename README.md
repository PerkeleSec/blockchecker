# IP Blocklist Checker

Script for checking IPs against DNS blocklists, contained in Docker.
Useful for email senders and for Email Web Security analysis/op-sec.

## Quick Start
To pull and run from Docker:
```bash
docker pull perke13/blockcheck:latest
docker run -it --rm -v "${PWD}:/app/input" perke13/blockcheck:latest
```
IMPORTANT For Apple Silicon (M1, M2...)
run with this docker command instead
```bash
docker pull perke13/blockcheck:latest
docker run -it --rm -v "${PWD}:/app/input" --platform linux/amd64 --tty perke13/blockcheck:latest
```
## File Paths
- Built-in txt sample in Docker to test file input: `/app/data/sample_ips.txt`

# Using the Tool

When asked, choose option 1 for single IP or 2 for file input, 3 to quit.
Input single IP or file path depending on chosen option.

*For file input test, use built-in path: /app/data/sample_ips.txt
If run locally will take local path also.
