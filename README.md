# awinrm

**Asynchronous Python library for Windows Remote Management (WinRM)**

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

`awinrm` is a fully asynchronous Python client for Windows Remote Management (WinRM). It allows you to execute commands, run PowerShell scripts, transfer files, and maintain interactive shell sessions on remote Windows machines.

## 🙏 Acknowledgements

This project is based on the excellent [pywinrm](https://github.com/diyan/pywinrm) library by Alexey Diyan and contributors. While `pywinrm` uses synchronous `requests` and external authentication libraries, `awinrm` was rewritten to be fully async with `httpx` and uses [asyauth](https://github.com/skelsec/asyauth) for authentication.

## ✨ Features

- **Fully Asynchronous** - Built with `asyncio` and `httpx` for non-blocking I/O
- **Pure Python Authentication** - NTLM, Kerberos, SPNEGO, and CredSSP are all implemented in pure Python via `asyauth` and `minikerberos` (no system dependencies like `krb5` or `sspi` required!)
- **Interactive Shells** - Create persistent CMD or PowerShell sessions with keepalive support
- **File Transfer** - Upload and download files via base64-encoded PowerShell commands
- **Message Encryption** - Automatic GSSAPI message encryption for secure communication over HTTP
- **Graceful Termination** - Clean handling of shell exits and session timeouts

## 📦 Installation

```bash
pip install awinrm
```

### Dependencies

All dependencies are pure Python:
- `httpx` - Async HTTP client
- `asyauth` - Pure Python implementation of NTLM, Kerberos, SPNEGO, CredSSP
- `unicrypto` - Cryptographic primitives
- `aioconsole` - Async console input for interactive shells

## 🔗 URL Format

`awinrm` uses URL-based credential specification (from `asyauth`). The format is:

```
<transport>+<auth_type>-<auth_method>://<username>:<password>@<host>:<port>/<path>?<options>
```

### Components

| Component | Description | Examples |
|-----------|-------------|----------|
| `transport` | HTTP or HTTPS | `http`, `https` |
| `auth_type` | Authentication protocol | `ntlm`, `kerberos`, `spnego` |
| `auth_method` | Credential type | `password`, `nt`, `aes`, `ccache` |
| `username` | User (with optional domain) | `user`, `DOMAIN\user`, `user@domain.com` |
| `password` | Password or hash | plaintext password or NT hash |
| `host` | Target hostname or IP | `192.168.1.100`, `server.domain.com` |
| `port` | WinRM port (optional) | `5985` (HTTP), `5986` (HTTPS) |
| `options` | Query parameters | `dc=`, `proxytype=`, etc. |

### URL Examples

```python
# NTLM with password (local account)
"http+ntlm-password://administrator:Password123@192.168.1.100"

# NTLM with domain account
"http+ntlm-password://MYDOMAIN\\admin:Password123@server.mydomain.com"

# Kerberos with password
"http+kerberos-password://NORTH\\vagrant:vagrant@winterfell.north.sevenkingdoms.local/?dc=192.168.56.11"

# Kerberos with ccache (ticket cache)
"http+kerberos-ccache://winterfell.north.sevenkingdoms.local/?ccache=/tmp/krb5cc_1000"

# NTLM with NT hash (pass-the-hash)
"http+ntlm-nt://administrator:aad3b435b51404eeaad3b435b51404ee@192.168.1.100"

# HTTPS with NTLM
"https+ntlm-password://admin:secret@secure-server.domain.com:5986"
```

### Query Parameters

| Parameter | Description |
|-----------|-------------|
| `dc=<ip>` | Domain controller IP (for Kerberos) |
| `ccache=<path>` | Path to Kerberos credential cache |
| `proxytype=<type>` | Proxy type (`socks5`, `http`) |
| `proxyhost=<host>` | Proxy hostname |
| `proxyport=<port>` | Proxy port |

## 📖 API Usage

### Basic Command Execution

```python
import asyncio
from awinrm import Session

async def main():
    url = "http+ntlm-password://administrator:Password123@192.168.1.100"
    
    async with Session(url) as session:
        # Run a command
        stdout, stderr, return_code = await session.run_cmd('ipconfig', ('/all',))
        print(stdout.decode())
        
        # Run PowerShell
        stdout, stderr, return_code = await session.run_ps('Get-Process | Select-Object -First 5')
        print(stdout.decode())

asyncio.run(main())
```

### Interactive Shell

```python
import asyncio
from awinrm import Session, ShellTerminatedError

async def main():
    url = "http+ntlm-password://administrator:Password123@192.168.1.100"
    
    async with Session(url) as session:
        # Create a CMD shell
        async with session.create_shell(shell_type='cmd') as shell:
            # Send commands
            await shell.send_input(b'whoami\r\n')
            
            # Read output
            stdout = await shell.stdout.get()
            print(stdout.decode())
            
            # Check if shell is still running
            if not shell.is_terminated:
                await shell.send_input(b'exit\r\n')

asyncio.run(main())
```

### PowerShell Shell

```python
async with Session(url) as session:
    # Create a PowerShell shell (recommended for most use cases)
    async with session.create_shell(shell_type='powershell') as shell:
        await shell.send_input(b'$PSVersionTable\r\n')
        stdout = await shell.stdout.get()
        print(stdout.decode())
```

### File Transfer

```python
async with Session(url) as session:
    # Upload a file
    await session.upload_file(
        local_path='/tmp/script.ps1',
        remote_path='C:\\temp\\script.ps1',
        progress_callback=lambda sent, total: print(f'{sent}/{total} bytes')
    )
    
    # Download a file
    await session.download_file(
        remote_path='C:\\Windows\\System32\\drivers\\etc\\hosts',
        local_path='/tmp/hosts'
    )
    
    # Check if file exists
    exists = await session.file_exists('C:\\temp\\script.ps1')
    
    # Get file size
    size = await session.get_file_size('C:\\temp\\script.ps1')
```

### Authentication Types

```python
# SPNEGO (auto-negotiates NTLM or Kerberos)
async with Session(url, authtype='spnego') as session:
    ...

# CredSSP (allows credential delegation / double-hop)
async with Session(url, authtype='credssp') as session:
    ...
```

### Shell Configuration

```python
async with Session(url) as session:
    shell = session.create_shell(
        shell_type='powershell',      # 'cmd', 'powershell', or 'pwsh'
        working_directory='C:\\temp',
        env_vars={'MY_VAR': 'value'},
        codepage=65001,               # UTF-8
        keepalive_interval=60,        # Seconds between keepalive pings
        idle_timeout=300,             # Server-side idle timeout
    )
    async with shell:
        ...
```

### Custom HTTP Transport

For advanced use cases (proxies, custom SSL, etc.):

```python
import httpx

transport = httpx.AsyncHTTPTransport(
    verify=False,
    http2=True,
)

async with Session(url, transport=transport, verify=False) as session:
    ...
```

### Exception Handling

```python
from awinrm import (
    Session,
    ShellTerminatedError,
    ShellNotFoundError,
    WinRMError,
    WinRMTransportError,
    AuthenticationError,
)

async with Session(url) as session:
    async with session.create_shell() as shell:
        try:
            await shell.send_input(b'exit\r\n')
            await shell.read_output()
        except ShellTerminatedError as e:
            print(f"Shell exited with code: {e.exit_code}")
        except ShellNotFoundError:
            print("Shell was closed by the server")
        except AuthenticationError:
            print("Authentication failed")
        except WinRMTransportError as e:
            print(f"HTTP error: {e.code}")
```

## 🛠️ Command-Line Tools

### awinrm-runcmd

Execute a single command on a remote host:

```bash
# Basic usage
awinrm-runcmd 'http+ntlm-password://admin:pass@192.168.1.100' 'ipconfig /all'

# With verbose output
awinrm-runcmd -v 'http+ntlm-password://admin:pass@192.168.1.100' 'whoami'

# Using CredSSP
awinrm-runcmd -a credssp 'http+ntlm-password://admin:pass@192.168.1.100' 'hostname'
```

### awinrm-cmdshell

Interactive remote shell:

```bash
# CMD shell
awinrm-cmdshell -s cmd 'http+ntlm-password://admin:pass@192.168.1.100'

# PowerShell shell (default)
awinrm-cmdshell 'http+ntlm-password://admin:pass@192.168.1.100'

# PowerShell Core
awinrm-cmdshell -s pwsh 'http+ntlm-password://admin:pass@192.168.1.100'

# With verbose logging
awinrm-cmdshell -v 'http+kerberos-password://DOMAIN\\user:pass@server/?dc=dc.domain.com'
```

### awinrm-authcheck

Test authentication without executing commands:

```bash
# Test NTLM
awinrm-authcheck 'http+ntlm-password://admin:pass@192.168.1.100'

# Test Kerberos
awinrm-authcheck 'http+kerberos-password://DOMAIN\\user:pass@server/?dc=dc.domain.com'

# Verbose mode
awinrm-authcheck -v 'http+ntlm-password://admin:pass@192.168.1.100'
```

## ⚙️ WinRM Server Configuration

### Enable WinRM (on the Windows target)

```powershell
# Quick setup (HTTP + NTLM)
winrm quickconfig -q

# Enable CredSSP (for credential delegation)
Enable-WSManCredSSP -Role Server -Force

# Check current config
winrm get winrm/config
```

### Firewall

WinRM uses:
- **Port 5985** for HTTP
- **Port 5986** for HTTPS

```powershell
# Allow WinRM through firewall
New-NetFirewallRule -Name "WinRM-HTTP" -DisplayName "WinRM (HTTP)" -Enabled True -Direction Inbound -Protocol TCP -LocalPort 5985 -Action Allow
```

## 🔐 Security Notes

1. **Use HTTPS in production** - HTTP transmits credentials in a recoverable format
2. **Prefer Kerberos** - More secure than NTLM, supports delegation
3. **Message encryption is automatic** - Even over HTTP, NTLM/Kerberos encrypt message payloads
4. **CredSSP allows delegation** - Use when you need to access network resources from the remote host

## 📚 API Reference

### Session

| Method | Description |
|--------|-------------|
| `run_cmd(command, args)` | Execute a command, return (stdout, stderr, rc) |
| `run_ps(script)` | Execute PowerShell script |
| `create_shell(shell_type, ...)` | Create interactive shell |
| `create_powershell(...)` | Convenience method for PowerShell shell |
| `upload_file(local, remote, callback)` | Upload file to remote |
| `download_file(remote, local, callback)` | Download file from remote |
| `file_exists(path)` | Check if remote file exists |
| `get_file_size(path)` | Get remote file size |

### WinRMShell

| Property/Method | Description |
|-----------------|-------------|
| `is_terminated` | True if shell has exited |
| `return_code` | Exit code (if terminated) |
| `send_input(data)` | Send bytes to shell stdin |
| `read_output()` | Read available stdout/stderr |
| `wait_for_termination()` | Block until shell exits |
| `close()` | Close the shell |

### Exceptions

| Exception | Description |
|-----------|-------------|
| `WinRMError` | Base exception for all WinRM errors |
| `WinRMTransportError` | HTTP-level errors (4xx, 5xx) |
| `ShellTerminatedError` | Shell has exited (includes exit_code) |
| `ShellNotFoundError` | Shell no longer exists on server |
| `AuthenticationError` | Authentication failed (401) |
| `WinRMOperationTimeoutError` | Operation timed out (retriable) |

## 📄 License

MIT License - see [LICENSE](LICENSE) for details.

