# macOS Platform Guide

This guide covers warmor's macOS implementation using the Endpoint Security Framework.

## Architecture

```
┌─────────────────────────────────────┐
│         WASM Policy Engine          │
│    (Portable, Platform-Agnostic)    │
└─────────────────────────────────────┘
                 │
                 ▼
┌─────────────────────────────────────┐
│    Platform Abstraction Layer       │
│         (interface.go)              │
└─────────────────────────────────────┘
                 │
                 ▼
┌─────────────────────────────────────┐
│     macOS Platform (darwin.go)      │
│    - ESF client management          │
│    - Event subscription             │
│    - Authorization responses        │
└─────────────────────────────────────┘
                 │
                 ▼
┌─────────────────────────────────────┐
│   Endpoint Security Framework       │
│    - System extension               │
│    - Event delivery                 │
│    - Authorization API              │
└─────────────────────────────────────┘
                 │
                 ▼
┌─────────────────────────────────────┐
│            macOS Kernel             │
│    - Process execution hooks        │
│    - File system hooks              │
│    - Network hooks                  │
└─────────────────────────────────────┘
```

## Current Status

⚠️ **Phase 4 - In Development**

The macOS platform is currently in stub mode. Full implementation will include:

- ✅ Platform abstraction layer (complete)
- 🚧 Endpoint Security Framework integration (planned)
- 🚧 Process monitoring (planned)
- 🚧 File system monitoring (planned)
- 🚧 Network monitoring (planned)
- 🚧 Authorization capabilities (planned)

## Requirements

### macOS Version
- **Minimum:** macOS 10.15 Catalina
- **Recommended:** macOS 12 Monterey or later
- **Optimal:** macOS 13 Ventura or later

### System Requirements
- **Architecture:** x86_64 or Apple Silicon (arm64)
- **SIP Status:** Disabled for development (see below)
- **Entitlements:** System extension entitlements required

### Check System
```bash
# Check macOS version
sw_vers

# Check architecture
uname -m

# Check SIP status
csrutil status
```

### Build Dependencies
```bash
# Install Xcode Command Line Tools
xcode-select --install

# Install Homebrew
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Install Go
brew install go

# Install Rust (for WASM policies)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

## System Integrity Protection (SIP)

### Development Mode
For development, SIP must be partially disabled:

```bash
# Reboot into Recovery Mode (Intel: Cmd+R, Apple Silicon: Hold power button)
# Open Terminal in Recovery Mode

# Disable SIP for system extensions
csrutil enable --without kext --without debug

# Reboot
reboot
```

⚠️ **Warning:** Only disable SIP on development machines. Production deployments should use proper code signing and notarization.

### Production Mode
For production, use:
- Valid Apple Developer ID
- System Extension entitlements
- Notarization
- User approval workflow

## Building

### 1. Build WASM Policy
```bash
cd policies/cross-platform
cargo build --release --target wasm32-unknown-unknown
```

### 2. Build warmor
```bash
GOOS=darwin GOARCH=arm64 go build -o warmor cmd/warmor/main.go
```

For Intel Macs:
```bash
GOOS=darwin GOARCH=amd64 go build -o warmor cmd/warmor/main.go
```

### 3. Code Signing (Production)
```bash
# Sign the binary
codesign --sign "Developer ID Application: Your Name" \
         --entitlements warmor.entitlements \
         --options runtime \
         warmor

# Verify signature
codesign --verify --verbose warmor
```

## Entitlements

Create `warmor.entitlements`:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>com.apple.developer.endpoint-security.client</key>
    <true/>
    <key>com.apple.security.cs.allow-unsigned-executable-memory</key>
    <true/>
    <key>com.apple.security.cs.disable-library-validation</key>
    <true/>
</dict>
</plist>
```

## Running

### Basic Usage (Stub Mode)
```bash
# Run with sudo
sudo ./warmor

# Run with custom policy
sudo ./warmor --policy /path/to/policy.wasm
```

### LaunchDaemon (System Service)
Create `/Library/LaunchDaemons/com.warmor.daemon.plist`:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.warmor.daemon</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/local/bin/warmor</string>
        <string>--policy</string>
        <string>/etc/warmor/policy.wasm</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
</dict>
</plist>
```

Load the daemon:
```bash
sudo launchctl load /Library/LaunchDaemons/com.warmor.daemon.plist
sudo launchctl start com.warmor.daemon
```

## Endpoint Security Framework (Planned)

### Event Types

#### Process Events
- `ES_EVENT_TYPE_AUTH_EXEC` - Process execution (authorization)
- `ES_EVENT_TYPE_NOTIFY_EXEC` - Process execution (notification)
- `ES_EVENT_TYPE_NOTIFY_FORK` - Process fork
- `ES_EVENT_TYPE_NOTIFY_EXIT` - Process exit

#### File Events
- `ES_EVENT_TYPE_AUTH_OPEN` - File open (authorization)
- `ES_EVENT_TYPE_AUTH_CREATE` - File creation (authorization)
- `ES_EVENT_TYPE_AUTH_UNLINK` - File deletion (authorization)
- `ES_EVENT_TYPE_NOTIFY_WRITE` - File write (notification)

#### Network Events
- `ES_EVENT_TYPE_AUTH_CONNECT` - Network connection (authorization)
- `ES_EVENT_TYPE_NOTIFY_BIND` - Socket bind (notification)

### Authorization vs Notification

**Authorization Events:**
- Can be allowed or denied
- Must respond within deadline (default: 60s)
- Block process until response
- Used for enforcement

**Notification Events:**
- Cannot be denied
- No response required
- Asynchronous delivery
- Used for monitoring

### Example Integration (Future)
```go
// Create ES client
client, err := es.NewClient(&es.ClientConfig{
    Name: "com.warmor.enforcer",
})

// Subscribe to events
client.Subscribe([]es.EventType{
    es.EventTypeAuthExec,
    es.EventTypeAuthOpen,
    es.EventTypeAuthConnect,
})

// Handle events
for event := range client.Events() {
    decision := evaluatePolicy(event)
    if event.IsAuth() {
        client.Respond(event, decision)
    }
}
```

## Monitoring Capabilities (Planned)

### Process Monitoring
**Captured Data:**
- Process ID (PID)
- Parent Process ID (PPID)
- User ID (UID)
- Group ID (GID)
- Executable path
- Arguments
- Environment variables
- Code signing information

**Example Event:**
```json
{
  "type": "process",
  "pid": 1234,
  "uid": 501,
  "gid": 20,
  "comm": "bash",
  "filename": "/bin/bash",
  "args": ["-c", "ls -la"]
}
```

### File System Monitoring
**Captured Data:**
- Process ID
- User ID
- File path
- Operation type
- Access mode
- File attributes

**Example Event:**
```json
{
  "type": "file",
  "pid": 1234,
  "uid": 501,
  "path": "/Users/user/Documents/sensitive.txt",
  "flags": 1
}
```

### Network Monitoring
**Captured Data:**
- Process ID
- User ID
- Local address/port
- Remote address/port
- Protocol

**Example Event:**
```json
{
  "type": "network",
  "pid": 1234,
  "uid": 501,
  "dest_ip": "192.168.1.100",
  "dest_port": 443
}
```

## Capabilities (Current)

```go
Capabilities{
    ProcessMonitoring: false,  // 🚧 Planned
    FileMonitoring:    false,  // 🚧 Planned
    NetworkMonitoring: false,  // 🚧 Planned
    Enforcement:       false,  // 🚧 Planned
}
```

## Security Considerations

### Privileges Required
- **root** - Required for ES client creation
- **System Extension** - Must be approved by user
- **Full Disk Access** - May be required for file monitoring

### User Approval
macOS requires user approval for system extensions:

1. System Preferences → Security & Privacy
2. Allow system extension from developer
3. Restart required

### Privacy Permissions
Grant necessary permissions:
```bash
# Full Disk Access
sudo tccutil reset SystemPolicyAllFiles

# Developer Tools
sudo DevToolsSecurity -enable
```

## Debugging

### Check System Extension
```bash
# List system extensions
systemextensionsctl list

# Check extension status
systemextensionsctl status

# Reset extensions (development only)
systemextensionsctl reset
```

### Enable Debug Logging
```bash
# Enable ES debug logging
sudo log config --mode "level:debug" --subsystem com.apple.endpoint-security

# View logs
log stream --predicate 'subsystem == "com.apple.endpoint-security"'
```

### Monitor Events
```bash
# Use eslogger (if available)
sudo eslogger exec open connect

# View system logs
log show --predicate 'process == "warmor"' --last 1h
```

## Performance

### Overhead
- **Per-event latency:** <50μs (notification), <500μs (authorization)
- **CPU overhead:** <2% on typical workloads
- **Memory overhead:** ~20MB for ES client

### Optimization Tips
1. **Use notification events** when enforcement not needed
2. **Cache decisions** to reduce policy evaluations
3. **Filter events** at subscription time
4. **Batch responses** for authorization events

## Limitations (Current)

1. **Stub Implementation** - No actual monitoring yet
2. **No Enforcement** - Cannot block operations
3. **Test Events Only** - Generates dummy events every 5 seconds
4. **No ES Client** - Waiting for CGO-free ES bindings

## Alternative Approaches

### 1. OpenBSM (Basic Security Module)
**Pros:**
- Native audit framework
- No special entitlements
- Historical data

**Cons:**
- Limited real-time capability
- No enforcement
- Complex audit trail parsing

### 2. FSEvents (File System Events)
**Pros:**
- File system monitoring
- No special permissions
- Low overhead

**Cons:**
- File events only
- No enforcement
- Delayed notifications

### 3. DTrace (Dynamic Tracing)
**Pros:**
- Powerful tracing
- Low overhead
- Flexible probes

**Cons:**
- SIP restrictions
- No enforcement
- Complex scripting

## Roadmap

### Phase 4.3 (Current)
- [x] Platform abstraction layer
- [x] macOS stub implementation
- [ ] ES Framework integration (CGO)
- [ ] Process monitoring
- [ ] Basic authorization

### Phase 5 (Future)
- [ ] CGO-free ES bindings
- [ ] File system monitoring
- [ ] Network monitoring
- [ ] Advanced authorization

### Phase 6 (Future)
- [ ] Apple Silicon optimization
- [ ] XPC service integration
- [ ] Transparency, Consent, and Control (TCC) integration
- [ ] Cloud integration (iCloud)

## Contributing

To contribute to macOS support:

1. **Test on Apple Silicon** - Ensure ARM64 compatibility
2. **ES Framework Bindings** - Help create CGO-free bindings
3. **Documentation** - Improve this guide
4. **Testing** - Test on different macOS versions

## References

- [Endpoint Security Framework](https://developer.apple.com/documentation/endpointsecurity)
- [System Extensions](https://developer.apple.com/documentation/systemextensions)
- [Code Signing Guide](https://developer.apple.com/library/archive/documentation/Security/Conceptual/CodeSigningGuide/)
- [Notarization](https://developer.apple.com/documentation/security/notarizing_macos_software_before_distribution)
- [TCC Database](https://www.rainforestqa.com/blog/macos-tcc-db-deep-dive)

## Support

For macOS-specific issues:
- GitHub Issues: Tag with `platform:macos`
- Discussions: Use `macOS Support` category
- Email: macos-support@warmor.dev