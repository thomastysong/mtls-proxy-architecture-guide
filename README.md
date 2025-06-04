# Building a Zero-Trust mTLS Proxy Architecture for Enterprise Device Fleets

## Introduction

In today's enterprise environments, securing communication between client applications and backend services is paramount. However, many legacy applications lack native TLS support, and retrofitting them with mutual TLS (mTLS) authentication can be complex and time-consuming. 

This post describes a clever solution: using Ghostunnel as a transparent mTLS proxy to secure these connections without modifying existing applications. We'll explore how to implement this architecture across fleets of macOS and Windows devices managed by Jamf and Intune respectively.

## The Challenge

Consider a typical enterprise scenario:
- Thousands of devices running various client applications
- Backend services requiring strong authentication
- Legacy applications that only speak HTTP
- Need for certificate-based device identity
- Requirement for centralized management and compliance

Traditional approaches would require:
- Modifying each application to support TLS
- Managing certificates within each application
- Dealing with different TLS implementations across platforms

## The Solution: mTLS Proxy Architecture

Instead of modifying applications, we introduce a proxy layer using [Ghostunnel](https://github.com/ghostunnel/ghostunnel), an open-source SSL/TLS proxy with mutual authentication support.

### Architecture Overview

```
┌─────────────────┐      HTTP       ┌──────────────┐      mTLS      ┌─────────────┐
│  Chef Client    │ ──────────────> │  Ghostunnel  │ ─────────────> │   Backend   │
│  localhost:32392│                  │  localhost:  │                 │   Server    │
└─────────────────┘                  │     9999     │                 │    :8443    │
                                     └──────────────┘                 └─────────────┘
                                            │
                                            │ Reads
                                            ▼
                                    ┌──────────────┐
                                    │ Certificate  │
                                    │    Store     │
                                    └──────────────┘
```

### Key Components

1. **Client Applications**: Continue using plain HTTP to localhost
2. **Ghostunnel**: Handles all TLS complexity and certificate management
3. **Certificate Store**: Platform-native certificate storage
4. **MDM Platform**: Manages certificate lifecycle and deployment

## Implementation Guide

### Prerequisites

- Jamf Pro for macOS management
- Microsoft Intune for Windows management
- Certificate Authority (CA) infrastructure
- Ghostunnel binaries for both platforms

### macOS Implementation (Jamf)

#### 1. Package Creation

First, create a package containing Ghostunnel and its LaunchDaemon:

```bash
#!/bin/bash
# build-ghostunnel-pkg.sh

PACKAGE_VERSION="1.0.0"
INSTALL_DIR="/usr/local/bin"
DAEMON_DIR="/Library/LaunchDaemons"

# Create package structure
mkdir -p ghostunnel-pkg/usr/local/bin
mkdir -p ghostunnel-pkg/Library/LaunchDaemons

# Copy binary
cp ghostunnel ghostunnel-pkg/usr/local/bin/

# Create LaunchDaemon
cat > ghostunnel-pkg/Library/LaunchDaemons/com.company.ghostunnel.plist << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.company.ghostunnel</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/local/bin/ghostunnel</string>
        <string>client</string>
        <string>--listen</string>
        <string>localhost:9999</string>
        <string>--target</string>
        <string>backend.company.com:8443</string>
        <string>--keystore</string>
        <string>/etc/ghostunnel/client.p12</string>
        <string>--cacert</string>
        <string>/etc/ghostunnel/ca.crt</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardErrorPath</key>
    <string>/var/log/ghostunnel.err</string>
    <key>StandardOutPath</key>
    <string>/var/log/ghostunnel.out</string>
</dict>
</plist>
EOF

# Build package
pkgbuild --root ghostunnel-pkg \
         --identifier com.company.ghostunnel \
         --version $PACKAGE_VERSION \
         ghostunnel-$PACKAGE_VERSION.pkg
```

#### 2. Certificate Configuration Profile

Create a Configuration Profile in Jamf to deploy certificates:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>PayloadContent</key>
    <array>
        <dict>
            <key>PayloadType</key>
            <string>com.apple.security.scep</string>
            <key>PayloadDisplayName</key>
            <string>Device Certificate</string>
            <key>PayloadIdentifier</key>
            <string>com.company.devicecert</string>
            <key>PayloadContent</key>
            <dict>
                <key>URL</key>
                <string>https://scep.company.com/certsrv/mscep/</string>
                <key>Subject</key>
                <array>
                    <array>
                        <string>CN</string>
                        <string>$SERIALNUMBER</string>
                    </array>
                </array>
                <key>KeySize</key>
                <integer>2048</integer>
                <key>KeyUsage</key>
                <integer>5</integer>
            </dict>
        </dict>
    </array>
</dict>
</plist>
```

#### 3. Jamf Policy Setup

Create a policy that:
- Deploys the Ghostunnel package
- Ensures the Configuration Profile is applied
- Runs at enrollment and check-in

```bash
# Extension Attribute to monitor service
#!/bin/bash

if launchctl list | grep -q "com.company.ghostunnel"; then
    status=$(launchctl list | grep "com.company.ghostunnel" | awk '{print $1}')
    if [ "$status" = "-" ]; then
        echo "<result>Running</result>"
    else
        echo "<result>Stopped (Exit: $status)</result>"
    fi
else
    echo "<result>Not Loaded</result>"
fi
```

### Windows Implementation (Intune)

#### 1. PowerShell Installation Script

Create a PowerShell script for deployment:

```powershell
# install-ghostunnel.ps1

param(
    [string]$InstallPath = "C:\Program Files\Ghostunnel",
    [string]$ServiceName = "GhostunnelProxy"
)

# Create installation directory
New-Item -ItemType Directory -Path $InstallPath -Force | Out-Null

# Copy binary (assume it's staged in Intune package)
Copy-Item -Path ".\ghostunnel.exe" -Destination $InstallPath -Force

# Create configuration file
$config = @"
{
    "listen": "localhost:9999",
    "target": "backend.company.com:8443",
    "keystore": "cert://LocalMachine/My",
    "keystoreSubject": "CN=*",
    "cacert": "cert://LocalMachine/Root/CompanyCA"
}
"@

$config | Out-File -FilePath "$InstallPath\config.json" -Encoding UTF8

# Install as Windows Service using NSSM
$nssmPath = ".\nssm.exe"
& $nssmPath install $ServiceName "$InstallPath\ghostunnel.exe" `
    "client" `
    "--config=$InstallPath\config.json"

# Configure service
& $nssmPath set $ServiceName AppStdout "$InstallPath\logs\service.log"
& $nssmPath set $ServiceName AppStderr "$InstallPath\logs\error.log"
& $nssmPath set $ServiceName AppRotateFiles 1
& $nssmPath set $ServiceName AppRotateBytes 10485760

# Start service
Start-Service -Name $ServiceName

# Set recovery options
sc.exe failure $ServiceName reset= 86400 actions= restart/60000/restart/60000/restart/60000
```

#### 2. Certificate Deployment via Intune

Configure SCEP certificate profile in Intune:

```json
{
  "certificateProfileName": "DeviceCertificate",
  "subject": "CN={{DeviceName}}",
  "keySize": 2048,
  "keyUsage": ["DigitalSignature", "KeyEncipherment"],
  "certificateValidityPeriod": {
    "value": 1,
    "unit": "Years"
  },
  "renewalThresholdPercentage": 20,
  "scepServerUrls": ["https://scep.company.com/certsrv/mscep/"]
}
```

#### 3. Compliance Detection Script

```powershell
# detect-ghostunnel.ps1

try {
    $service = Get-Service -Name "GhostunnelProxy" -ErrorAction Stop
    
    if ($service.Status -eq "Running") {
        # Check certificate validity
        $certs = Get-ChildItem Cert:\LocalMachine\My | 
                 Where-Object { $_.Subject -match $env:COMPUTERNAME }
        
        $validCert = $certs | Where-Object { 
            $_.NotAfter -gt (Get-Date).AddDays(7) -and 
            $_.HasPrivateKey 
        }
        
        if ($validCert) {
            Write-Host "Ghostunnel is running with valid certificate"
            exit 0
        } else {
            Write-Host "Certificate is expired or missing"
            exit 1
        }
    } else {
        Write-Host "Ghostunnel service is not running"
        exit 1
    }
} catch {
    Write-Host "Ghostunnel service not found"
    exit 1
}
```

### Application Configuration

Update your applications to use the local proxy:

```yaml
# chef-client.rb
chef_server_url "http://localhost:9999"
node_name "device-name"
client_key "/etc/chef/client.pem"

# The connection is now proxied through Ghostunnel
# which handles mTLS to the actual Chef server
```

## Multi-Service Support

For multiple backend services, run separate Ghostunnel instances:

```bash
# Service 1: Chef
ghostunnel client \
  --listen localhost:9999 \
  --target chef.company.com:8443 \
  --keystore /etc/certs/device.p12

# Service 2: Software Updates  
ghostunnel client \
  --listen localhost:9998 \
  --target updates.company.com:8443 \
  --keystore /etc/certs/device.p12

# Service 3: Configuration
ghostunnel client \
  --listen localhost:9997 \
  --target config.company.com:8443 \
  --keystore /etc/certs/device.p12
```

## Monitoring and Observability

### Centralized Logging

Configure Ghostunnel to send logs to your SIEM:

```yaml
# ghostunnel-config.yaml
logging:
  level: info
  format: json
  output: syslog
  syslog:
    address: "siem.company.com:514"
    facility: local0
    tag: ghostunnel
```

### Metrics Collection

Ghostunnel exposes Prometheus metrics:

```bash
ghostunnel client \
  --listen localhost:9999 \
  --target backend:8443 \
  --metrics-listen localhost:9090 \
  --keystore /etc/certs/device.p12
```

### Health Checks

Implement health check endpoints:

```go
// health-check-server.go
package main

import (
    "fmt"
    "net/http"
    "os/exec"
)

func healthCheck(w http.ResponseWriter, r *http.Request) {
    // Check if Ghostunnel is running
    cmd := exec.Command("pgrep", "-x", "ghostunnel")
    if err := cmd.Run(); err != nil {
        w.WriteHeader(http.StatusServiceUnavailable)
        fmt.Fprintf(w, "Ghostunnel not running")
        return
    }
    
    // Test backend connectivity
    resp, err := http.Get("http://localhost:9999/health")
    if err != nil || resp.StatusCode != 200 {
        w.WriteHeader(http.StatusServiceUnavailable)
        fmt.Fprintf(w, "Backend unreachable")
        return
    }
    
    w.WriteHeader(http.StatusOK)
    fmt.Fprintf(w, "Healthy")
}

func main() {
    http.HandleFunc("/health", healthCheck)
    http.ListenAndServe(":8080", nil)
}
```

## Security Considerations

### Certificate Pinning

Pin the backend server certificate for additional security:

```bash
ghostunnel client \
  --listen localhost:9999 \
  --target backend:8443 \
  --keystore device.p12 \
  --cacert ca.crt \
  --verify-cn backend.company.com
```

### Access Control

Restrict Ghostunnel to localhost only:

```bash
# macOS
pfctl -e
echo "block in proto tcp to port 9999" | pfctl -f -

# Windows
netsh advfirewall firewall add rule \
  name="Block Ghostunnel External" \
  dir=in \
  action=block \
  protocol=TCP \
  localport=9999 \
  remoteip=!127.0.0.1
```

### Audit Logging

Enable comprehensive audit logging:

```json
{
  "audit": {
    "enabled": true,
    "log_successful_connections": true,
    "log_failed_connections": true,
    "include_client_cert": true,
    "include_request_headers": false
  }
}
```

## Benefits of This Architecture

1. **Zero Code Changes**: Legacy applications work without modification
2. **Centralized Certificate Management**: MDM platforms handle all certificate lifecycle
3. **Platform Agnostic**: Same architecture works on macOS and Windows
4. **Strong Authentication**: Every connection is mutually authenticated
5. **Compliance Ready**: Easy to audit and monitor all connections
6. **Scalable**: Add new services by spinning up additional proxy instances

## Troubleshooting

### Common Issues

#### Certificate Not Found
```bash
# macOS
security find-certificate -a | grep "Subject:"

# Windows
certutil -store My
```

#### Connection Refused
```bash
# Check if Ghostunnel is listening
netstat -an | grep 9999

# Check logs
# macOS: /var/log/ghostunnel.err
# Windows: C:\Program Files\Ghostunnel\logs\error.log
```

#### Certificate Validation Failures
```bash
# Test certificate chain
openssl s_client -connect backend:8443 -showcerts

# Verify client certificate
openssl x509 -in client.pem -text -noout
```

## Conclusion

This mTLS proxy architecture provides a robust, secure solution for enterprise environments. By leveraging Ghostunnel and native MDM capabilities, we can secure legacy applications without code changes while maintaining centralized control and visibility.

The architecture is particularly powerful because it:
- Requires no application modifications
- Leverages existing MDM infrastructure
- Provides strong mutual authentication
- Scales to thousands of devices
- Maintains compliance requirements

As organizations continue to adopt Zero Trust principles, this pattern becomes increasingly valuable for securing device-to-server communications at scale.

## Additional Resources

- [Ghostunnel Documentation](https://github.com/ghostunnel/ghostunnel)
- [Jamf SCEP Configuration](https://docs.jamf.com/jamf-pro/documentation/)
- [Intune Certificate Deployment](https://docs.microsoft.com/en-us/mem/intune/)
- [mTLS Best Practices](https://www.cloudflare.com/learning/access-management/what-is-mutual-tls/)

---

*Have you implemented a similar architecture? Share your experiences and lessons learned in the comments below!* 
