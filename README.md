# sshproxy

A lightweight SSH proxy/bastion server with per-user ACL controls. Authenticates users via public key or password, then forwards connections to whitelisted backend hosts via TCP tunnel.

## Features

- Public key and password authentication
- Per-user host whitelists with wildcard support
- TCP tunnel mode (raw forwarding after auth)
- Multiple username formats for specifying target hosts
- Connection logging and statistics
- Single static binary

## Quick Start

```bash
# Build
./build.sh

# Generate host key
./sshproxy -genkey

# Copy and edit config
cp config.example.json config.json
# Edit config.json with your users/hosts

# Run
./sshproxy -config config.json
```

## Client Usage

```bash
# Specify target host in username
ssh server.com+myuser@proxy-host:2222

# Use default host from config
ssh myuser@proxy-host:2222
```

## Documentation

- [INSTALL.md](INSTALL.md) - Installation instructions
- [HOWTO.md](HOWTO.md) - Configuration and usage guide

## License

MIT
