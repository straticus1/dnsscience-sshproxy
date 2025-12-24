# HOWTO

## Configuration

The proxy uses a JSON configuration file. See `config.example.json` for a template.

### Config Structure

```json
{
  "listen_addr": ":2222",
  "host_key_path": "host_key",
  "users": []
}
```

| Field | Description | Default |
|-------|-------------|---------|
| `listen_addr` | Address and port to listen on | `:2222` |
| `host_key_path` | Path to SSH host private key | required |
| `users` | Array of user definitions | required |

### User Definition

```json
{
  "login_id": "username",
  "allowed_hosts": ["host1.com", "*.internal.com"],
  "default_host": "host1.com",
  "public_keys": ["ssh-ed25519 AAAA..."],
  "password_hash": "$2a$10$..."
}
```

| Field | Description |
|-------|-------------|
| `login_id` | Username for authentication (case-insensitive) |
| `allowed_hosts` | List of hosts this user can access |
| `default_host` | Host to connect to when none specified |
| `public_keys` | Authorized public keys (OpenSSH format) |
| `password_hash` | Bcrypt hash of password |

### Host Wildcards

- `*` - Allow access to any host
- `*.example.com` - Allow any subdomain of example.com

## Client Connection

### Username Formats

The target host can be specified in the SSH username:

```bash
# Format: targethost+loginid
ssh server.example.com+ryan@proxy:2222

# Format: loginid/targethost
ssh ryan/server.example.com@proxy:2222

# Format: loginid%targethost
ssh ryan%server.example.com@proxy:2222

# No target (uses default_host)
ssh ryan@proxy:2222
```

### Specifying Backend User

To connect as a different user on the backend:

```bash
# Format: backenduser@targethost+loginid
ssh admin@server.com+ryan@proxy:2222
```

## Password Hashing

Generate bcrypt password hashes:

```bash
./sshproxy -hashpw "mypassword"
```

Copy the output to the `password_hash` field in your config.

## Host Key Generation

```bash
./sshproxy -genkey -keyout /path/to/host_key
```

This generates a 4096-bit RSA key. Keep this key secure and consistent across restarts to avoid SSH host key warnings for clients.

## Logging

All connections and auth events are logged to stdout:

```
[SERVER] Listening on :2222
[CONN] New connection from 192.168.1.100:54321 (active: 1, total: 1)
[AUTH] Success: "ryan" via pubkey from 192.168.1.100:54321
[PROXY] "ryan" -> server.example.com (user: )
[PROXY] Connected "ryan" to server.example.com:22
[PROXY] Session ended for "ryan" -> server.example.com
```

## Running as a Service

### systemd

```ini
[Unit]
Description=SSH Proxy
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/sshproxy -config /etc/sshproxy/config.json
Restart=always
User=sshproxy
Group=sshproxy

[Install]
WantedBy=multi-user.target
```

### launchd (macOS)

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.hostscience.sshproxy</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/local/bin/sshproxy</string>
        <string>-config</string>
        <string>/etc/sshproxy/config.json</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
</dict>
</plist>
```
