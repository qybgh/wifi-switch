import Foundation
import CoreWLAN
import Security

private let toolName = "wifi-switch"
private let keychainService = "com.luoranyau.wifi-switch"

private enum ExitCode: Int32 {
    case usage = 2
    case keychain = 3
    case network = 4
    case verification = 5
}

private func fail(_ message: String, code: ExitCode) -> Never {
    if let data = "\(toolName): \(message)\n".data(using: .utf8) {
        FileHandle.standardError.write(data)
    }
    exit(code.rawValue)
}

private func usage() -> Never {
    print(
        """
        Usage:
          \(toolName) list
          \(toolName) status
          \(toolName) set <SSID>
          \(toolName) forget <SSID>
          \(toolName) <SSID>

        `set` prompts for the Wi-Fi password without echoing it and stores
        it in the user's login keychain. `\(toolName) <SSID>` connects using
        the saved password.
        """
    )
    exit(0)
}

private func run(_ executable: String, _ arguments: [String]) -> (Int32, String) {
    let process = Process()
    let pipe = Pipe()
    process.executableURL = URL(fileURLWithPath: executable)
    process.arguments = arguments
    process.standardOutput = pipe
    process.standardError = pipe
    do {
        try process.run()
        process.waitUntilExit()
    } catch {
        fail("failed to launch \(executable): \(error.localizedDescription)", code: .network)
    }
    let data = pipe.fileHandleForReading.readDataToEndOfFile()
    return (process.terminationStatus, String(data: data, encoding: .utf8) ?? "")
}

private func detectWiFiInterface() -> String {
    let (status, output) = run("/usr/sbin/networksetup", ["-listallhardwareports"])
    guard status == 0 else {
        fail("could not list hardware ports", code: .network)
    }
    let lines = output.components(separatedBy: .newlines)
    for (index, line) in lines.enumerated() {
        if line == "Hardware Port: Wi-Fi" || line == "Hardware Port: AirPort" {
            guard index + 1 < lines.count else { break }
            let deviceLine = lines[index + 1].trimmingCharacters(in: .whitespaces)
            if deviceLine.hasPrefix("Device: ") {
                let device = String(deviceLine.dropFirst("Device: ".count))
                    .trimmingCharacters(in: .whitespacesAndNewlines)
                if !device.isEmpty {
                    return device
                }
            }
        }
    }
    fail("could not detect a Wi-Fi interface", code: .network)
}

private func currentNetwork(interface: String) -> String? {
    let (_, output) = run("/usr/sbin/networksetup", ["-getairportnetwork", interface])
    let marker = "Current Wi-Fi Network: "
    guard let range = output.range(of: marker) else {
        return nil
    }
    return String(output[range.upperBound...])
        .trimmingCharacters(in: .whitespacesAndNewlines)
}

private struct Observation {
    let ssid: String?
    let bssid: String?
    let security: String?
    let ipv4: String?
    let gateway: String?
    let channel: Int?
    let active: Bool

    var fingerprint: String {
        "\(ipv4 ?? "")|\(gateway ?? "")|\(bssid ?? "")"
    }
}

private func redacted(_ value: String) -> Bool {
    value == "<redacted>" || value.isEmpty
}

private func observe(interface: String) -> Observation {
    let (_, summary) = run("/usr/sbin/ipconfig", ["getsummary", interface])

    func field(_ key: String) -> String? {
        for line in summary.components(separatedBy: .newlines) {
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            if trimmed.hasPrefix("\(key) :") {
                let value = trimmed.dropFirst("\(key) :".count)
                    .trimmingCharacters(in: .whitespaces)
                return redacted(value) ? nil : value
            }
        }
        return nil
    }

    let ssid = field("SSID")
    let bssid = field("BSSID")
    let security = field("Security")
    let router = field("Router")
    let (_, address) = run("/usr/sbin/ipconfig", ["getifaddr", interface])
    let ipv4 = address.trimmingCharacters(in: .whitespacesAndNewlines)

    let (_, status) = run("/usr/sbin/networksetup", ["-getairportpower", interface])
    let powered = status.trimmingCharacters(in: .whitespacesAndNewlines).contains(": On")
    let coreChannel = CWWiFiClient.shared().interface(withName: interface)?
        .wlanChannel()?.channelNumber

    return Observation(
        ssid: ssid ?? currentNetwork(interface: interface),
        bssid: bssid,
        security: security,
        ipv4: ipv4.isEmpty ? nil : ipv4,
        gateway: router,
        channel: coreChannel,
        active: powered && !ipv4.isEmpty
    )
}

private func targetChannels(for ssid: String, on interface: String) -> Set<Int>? {
    guard let core = CWWiFiClient.shared().interface(withName: interface) else {
        return nil
    }
    let networks: Set<CWNetwork>
    do {
        networks = try core.scanForNetworks(withName: ssid, includeHidden: true)
    } catch {
        return nil
    }
    let channels = Set(networks.compactMap { $0.wlanChannel?.channelNumber })
    return channels.isEmpty ? nil : channels
}

private func likelyConnected(to ssid: String, observation: Observation, interface: String) -> Bool {
    guard let channel = observation.channel else {
        return false
    }
    return targetChannels(for: ssid, on: interface)?.contains(channel) == true
}

private func keychainQuery(for ssid: String) -> [CFString: Any] {
    [
        kSecClass: kSecClassGenericPassword,
        kSecAttrService: keychainService,
        kSecAttrAccount: ssid,
    ]
}

private func loadPassword(for ssid: String) -> String? {
    var query = keychainQuery(for: ssid)
    query[kSecReturnData] = true
    query[kSecMatchLimit] = kSecMatchLimitOne

    var result: CFTypeRef?
    let status = SecItemCopyMatching(query as CFDictionary, &result)
    if status == errSecItemNotFound {
        return nil
    }
    guard status == errSecSuccess else {
        fail("keychain read failed for \(ssid): OSStatus \(status)", code: .keychain)
    }
    guard let data = result as? Data, let password = String(data: data, encoding: .utf8) else {
        fail("keychain item for \(ssid) is not valid UTF-8", code: .keychain)
    }
    return password
}

private func savePassword(_ password: String, for ssid: String) {
    let data = Data(password.utf8)
    let query = keychainQuery(for: ssid) as CFDictionary
    let attributes: [CFString: Any] = [
        kSecValueData: data,
        kSecAttrLabel: "\(toolName): \(ssid)",
        kSecAttrDescription: "Wi-Fi password for \(ssid)",
    ]

    var status = SecItemUpdate(query, attributes as CFDictionary)
    if status == errSecItemNotFound {
        var item = keychainQuery(for: ssid)
        attributes.forEach { item[$0.key] = $0.value }
        status = SecItemAdd(item as CFDictionary, nil)
    }
    guard status == errSecSuccess else {
        fail("keychain write failed for \(ssid): OSStatus \(status)", code: .keychain)
    }
}

private func forgetPassword(for ssid: String) {
    let status = SecItemDelete(keychainQuery(for: ssid) as CFDictionary)
    if status == errSecItemNotFound {
        print("No saved password for \(ssid).")
        return
    }
    guard status == errSecSuccess else {
        fail("keychain delete failed for \(ssid): OSStatus \(status)", code: .keychain)
    }
    print("Deleted saved password for \(ssid).")
}

private func listSaved() {
    let query: [CFString: Any] = [
        kSecClass: kSecClassGenericPassword,
        kSecAttrService: keychainService,
        kSecReturnAttributes: true,
        kSecMatchLimit: kSecMatchLimitAll,
    ]
    var result: CFTypeRef?
    let status = SecItemCopyMatching(query as CFDictionary, &result)
    if status == errSecItemNotFound {
        print("No saved Wi-Fi passwords.")
        return
    }
    guard status == errSecSuccess else {
        fail("keychain list failed: OSStatus \(status)", code: .keychain)
    }
    let items = (result as? [[CFString: Any]]) ?? []
    let ssids = items.compactMap { $0[kSecAttrAccount] as? String }.sorted()
    for ssid in ssids {
        print(ssid)
    }
}

private func readHiddenLine(prompt: String) -> String {
    FileHandle.standardError.write(prompt.data(using: .utf8)!)
    var original = termios()
    guard tcgetattr(STDIN_FILENO, &original) == 0 else {
        fail("could not read terminal settings", code: .verification)
    }
    var hidden = original
    hidden.c_lflag &= ~UInt(ECHO)
    guard tcsetattr(STDIN_FILENO, TCSAFLUSH, &hidden) == 0 else {
        fail("could not disable terminal echo", code: .verification)
    }
    defer {
        tcsetattr(STDIN_FILENO, TCSAFLUSH, &original)
        FileHandle.standardError.write("\n".data(using: .utf8)!)
    }
    guard let line = readLine(strippingNewline: true) else {
        fail("no password entered", code: .verification)
    }
    return line
}

private func connect(ssid: String) {
    guard let password = loadPassword(for: ssid) else {
        fail("no saved password for \(ssid); run `\(toolName) set \"\(ssid)\"` first", code: .keychain)
    }

    let interface = detectWiFiInterface()
    let initial = observe(interface: interface)
    if initial.ssid == ssid || likelyConnected(to: ssid, observation: initial, interface: interface) {
        print("Already connected to \(ssid) using \(interface).")
        return
    }

    let before = initial.fingerprint

    let (status, output) = run(
        "/usr/sbin/networksetup",
        ["-setairportnetwork", interface, ssid, password]
    )
    let message = output.trimmingCharacters(in: .whitespacesAndNewlines)
    if status != 0 ||
        message.localizedCaseInsensitiveContains("Failed to join") ||
        message.localizedCaseInsensitiveContains("Could not find network")
    {
        fail(message.isEmpty ? "networksetup failed" : message, code: .network)
    }

    Thread.sleep(forTimeInterval: 3)
    let deadline = Date().addingTimeInterval(12)
    var sawTargetSSID = false
    var sawChangedFingerprint = false
    while Date() < deadline {
        let after = observe(interface: interface)
        if after.ssid == ssid {
            sawTargetSSID = true
        }
        if likelyConnected(to: ssid, observation: after, interface: interface) {
            sawTargetSSID = true
        }
        if after.fingerprint != before {
            sawChangedFingerprint = true
        }
        if after.ssid == ssid || sawChangedFingerprint {
            let confidence = sawTargetSSID ? "confirmed" : "changed"
            print("Connected to \(ssid) using \(interface) (\(confidence)).")
            return
        }
        Thread.sleep(forTimeInterval: 0.5)
    }
    let final = observe(interface: interface)
    if final.active, final.fingerprint == before {
        fail("join was not observed; the link stayed on the previous network", code: .verification)
    }
    fail("networksetup did not report an error, but \(ssid) was not confirmed within 15 seconds", code: .verification)
}

let args = CommandLine.arguments.dropFirst()
guard let first = args.first else {
    usage()
}

switch first {
case "-h", "--help", "help":
    usage()
case "list":
    guard args.count == 1 else {
        fail("usage: \(toolName) list", code: .usage)
    }
    listSaved()
case "status":
    guard args.count == 1 else {
        fail("usage: \(toolName) status", code: .usage)
    }
    let interface = detectWiFiInterface()
    let state = observe(interface: interface)
    print("interface: \(interface)")
    print("active: \(state.active)")
    print("ssid: \(state.ssid ?? "<unavailable>")")
    print("bssid: \(state.bssid ?? "<unavailable>")")
    print("security: \(state.security ?? "<unavailable>")")
    print("ipv4: \(state.ipv4 ?? "<unavailable>")")
    print("gateway: \(state.gateway ?? "<unavailable>")")
case "set":
    guard args.count == 2 else {
        fail("usage: \(toolName) set <SSID>", code: .usage)
    }
    let ssid = String(args[args.index(after: args.startIndex)])
    let password = readHiddenLine(prompt: "Wi-Fi password for \(ssid): ")
    guard !password.isEmpty else {
        fail("password cannot be empty", code: .usage)
    }
    savePassword(password, for: ssid)
    print("Saved password for \(ssid).")
case "forget":
    guard args.count == 2 else {
        fail("usage: \(toolName) forget <SSID>", code: .usage)
    }
    forgetPassword(for: String(args[args.index(after: args.startIndex)]))
default:
    guard args.count == 1 else {
        usage()
    }
    connect(ssid: first)
}
