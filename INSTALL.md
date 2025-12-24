# Installation

## Requirements

- Go 1.21 or later

## Building from Source

```bash
# Clone the repository
git clone https://github.com/hostscience/sshproxy.git
cd sshproxy

# Build
./build.sh

# Or manually
go mod tidy
go build -o sshproxy .
```

## Cross-Compilation

Build for different platforms:

```bash
# Linux AMD64
GOOS=linux GOARCH=amd64 go build -o sshproxy-linux-amd64 .

# Linux ARM64
GOOS=linux GOARCH=arm64 go build -o sshproxy-linux-arm64 .

# macOS AMD64
GOOS=darwin GOARCH=amd64 go build -o sshproxy-darwin-amd64 .

# macOS ARM64 (Apple Silicon)
GOOS=darwin GOARCH=arm64 go build -o sshproxy-darwin-arm64 .
```

## Installation Steps

1. Build the binary:
   ```bash
   ./build.sh
   ```

2. Generate a host key:
   ```bash
   ./sshproxy -genkey -keyout host_key
   ```

3. Create configuration:
   ```bash
   cp config.example.json config.json
   # Edit config.json
   ```

4. (Optional) Hash passwords:
   ```bash
   ./sshproxy -hashpw "userpassword"
   # Add output to config.json
   ```

5. Run the proxy:
   ```bash
   ./sshproxy -config config.json
   ```

## System Installation

```bash
# Copy binary
sudo cp sshproxy /usr/local/bin/

# Create config directory
sudo mkdir -p /etc/sshproxy

# Copy and edit config
sudo cp config.example.json /etc/sshproxy/config.json
sudo cp host_key /etc/sshproxy/
sudo chmod 600 /etc/sshproxy/host_key

# Create service user (Linux)
sudo useradd -r -s /bin/false sshproxy
sudo chown -R sshproxy:sshproxy /etc/sshproxy
```

## Firewall

Ensure the listen port (default 2222) is accessible:

```bash
# iptables
sudo iptables -A INPUT -p tcp --dport 2222 -j ACCEPT

# ufw
sudo ufw allow 2222/tcp

# firewalld
sudo firewall-cmd --permanent --add-port=2222/tcp
sudo firewall-cmd --reload
```
