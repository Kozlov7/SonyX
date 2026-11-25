import Foundation

/// Одно установленное TCP-соединение.
public struct Connection: Hashable {
    public let pid: pid_t
    public let command: String
    public let localAddress: String
    public let remoteAddress: String
    public let remotePort: Int

    public init(pid: pid_t, command: String, localAddress: String, remoteAddress: String, remotePort: Int) {
        self.pid = pid; self.command = command; self.localAddress = localAddress; self.remoteAddress = remoteAddress; self.remotePort = remotePort
    }
}

public enum Connections {
    /// Установленные TCP-соединения процессов текущего пользователя (через `lsof`).
    public static func established() -> [Connection] {
        let result = Shell.run("/usr/sbin/lsof", [
            "-nP", "-iTCP", "-sTCP:ESTABLISHED", "-a", "-u", String(getuid()), "-F", "pcn",
        ])
        guard result.status == 0 || !result.stdout.isEmpty else { return [] }

        var connections: [Connection] = []
        var pid: pid_t = 0
        var command = ""
        for line in result.stdout.split(separator: "\n") {
            guard let tag = line.first else { continue }
            let value = String(line.dropFirst())
            switch tag {
            case "p": pid = pid_t(value) ?? 0
            case "c": command = value
            case "n":
                // Вид: 192.168.0.10:59436->192.0.2.42:443 ; IPv6 в квадратных скобках.
                guard let arrow = value.range(of: "->") else { continue }
                let local = String(value[..<arrow.lowerBound])
                let remote = String(value[arrow.upperBound...])
                guard let (localIP, _) = split(local), let (remoteIP, remotePort) = split(remote) else { continue }
                connections.append(Connection(pid: pid, command: command, localAddress: localIP, remoteAddress: remoteIP, remotePort: remotePort))
            default: break
            }
        }
        return connections
    }

    private static func split(_ endpoint: String) -> (String, Int)? {
        if endpoint.hasPrefix("[") {
            guard let close = endpoint.firstIndex(of: "]") else { return nil }
            let ip = String(endpoint[endpoint.index(after: endpoint.startIndex)..<close])
            let port = Int(endpoint[endpoint.index(close, offsetBy: 2)...]) ?? 0
            return (ip, port)
        }
        guard let colon = endpoint.lastIndex(of: ":") else { return nil }
        return (String(endpoint[..<colon]), Int(endpoint[endpoint.index(after: colon)...]) ?? 0)
    }
}

/// Проверка 2 из CHECKS.md: адрес сервера VPN.
///
/// При поднятом туннеле программы ходят в сеть с фиктивного адреса туннеля (198.18.x.x),
/// и только сам VPN-клиент держит соединения с физического адреса (192.168.x.x) наружу.
/// Среди них есть и прямые — к сайтам, которые клиент по своим правилам пускает мимо VPN.
/// Сервер VPN — тот публичный адрес, к которому больше всего соединений, и он держится
/// от проверки к проверке. Это эвристика; её ограничения описаны в CHECKS.md.
public final class ServerDetector {
    public struct Candidate: Equatable {
        public let address: String
        public let connections: Int
        public let command: String
        public init(address: String, connections: Int, command: String) {
            self.address = address; self.connections = connections; self.command = command
        }
    }

    /// Текущий сервер. Меняется только когда новый лидер держится два подсчёта подряд.
    public private(set) var current: Candidate?
    private var pendingLeader: String?
    /// Сколько раз подряд лидер не совпадал с текущим.
    private var pendingCount = 0
    public static let switchAfter = 2
    public static let minimumConnections = 2

    public init() {}

    @discardableResult
    public func update(with connections: [Connection]) -> Candidate? {
        var counts: [String: (count: Int, command: String)] = [:]
        for c in connections {
            // Исходящие с физического интерфейса на публичный адрес.
            guard !GeoIP.isPrivate(c.remoteAddress),
                  !c.remoteAddress.contains(":"),           // пока только IPv4
                  GeoIP.isPrivate(c.localAddress),
                  !c.localAddress.hasPrefix("198.18."), !c.localAddress.hasPrefix("198.19."),
                  !c.localAddress.hasPrefix("127.")
            else { continue }
            counts[c.remoteAddress, default: (0, c.command)].count += 1
        }
        guard let leader = counts.max(by: { $0.value.count < $1.value.count }),
              leader.value.count >= Self.minimumConnections
        else {
            // Нет данных (туннель простаивает) — оставляем прежний сервер.
            pendingLeader = nil
            pendingCount = 0
            return current
        }

        let candidate = Candidate(address: leader.key, connections: leader.value.count, command: leader.value.command)
        if current == nil {
            current = candidate
        } else if candidate.address == current?.address {
            current = candidate
            pendingLeader = nil
            pendingCount = 0
        } else {
            if pendingLeader == candidate.address { pendingCount += 1 } else { pendingLeader = candidate.address; pendingCount = 1 }
            if pendingCount >= Self.switchAfter {
                current = candidate
                pendingLeader = nil
                pendingCount = 0
            }
        }
        return current
    }

    public func reset() {
        current = nil
        pendingLeader = nil
        pendingCount = 0
    }
}
