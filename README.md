# wifi-switch

A small macOS command-line tool for switching between known Wi-Fi networks
without putting the Wi-Fi password in your shell history.

`wifi-switch` stores passwords in your login Keychain under its own namespace,
automatically detects the Wi-Fi interface, and switches networks with
`networksetup`.

## Requirements

- macOS
- Swift toolchain (Xcode Command Line Tools or Xcode)
- A saved password for the target SSID

## Install

```sh
make install
```

The default install path is `/opt/homebrew/bin/wifi-switch`. Override it with:

```sh
make install PREFIX=/usr/local/bin
```

You can also build only:

```sh
make
./build/wifi-switch --help
```

## Usage

Save a password once:

```sh
wifi-switch set "My Wi-Fi"
```

The password prompt does not echo the password.

Switch to a saved network:

```sh
wifi-switch "My Wi-Fi"
```

List saved SSIDs:

```sh
wifi-switch list
```

Delete one saved password:

```sh
wifi-switch forget "My Wi-Fi"
```

## How it works

1. The Wi-Fi interface is detected from `networksetup -listallhardwareports`.
2. The password is read from the login Keychain under the service
   `com.luoranyau.wifi-switch`.
3. The switch is performed with:

   ```sh
   networksetup -setairportnetwork <detected-interface> <SSID> <password>
   ```

4. The tool rejects explicit `networksetup` failures such as:
   - `Failed to join ...`
   - `Could not find network ...`

5. When `networksetup` exits successfully, the tool waits briefly and checks
   the current SSID or the network fingerprint (IPv4 address, default gateway,
   and Wi-Fi channel). This avoids reporting success when the command exits
   with status 0 but no usable switch occurred.

## Exit codes

| Code | Meaning |
| ---: | --- |
| `0` | Success |
| `2` | Invalid usage |
| `3` | Keychain read/write error or missing saved password |
| `4` | Network operation failed |
| `5` | The command could not be verified |

## Security notes

- Passwords are **not** accepted as command-line arguments.
- Passwords are not intended to appear in shell history.
- Passwords are stored as generic-password items in the login Keychain.
- The tool does not enumerate or modify Wi-Fi passwords stored by macOS for
  other applications.

macOS may ask for permission the first time an installed binary reads its
Keychain item. Use a stable install path and stable code signing identity if
you want that permission to remain valid across updates.

## Known limitations

- macOS Wi-Fi behavior varies between releases.
- Switching can briefly interrupt connectivity while the system associates and
  renews DHCP.
- On some macOS versions, `networksetup -getairportnetwork` does not report the
  current SSID reliably. The fingerprint check is a fallback for that case.
- This tool is macOS-only.

## Development

```sh
make
make check
```

`make check` compiles the source and runs non-network checks.

## License

MIT
