import Foundation
import Network

/// Проверки 3, 4, 5 из CHECKS.md. Всё локально, без запросов наружу.
public enum Diagnostics {
    public struct IPv6Status: Equatable {
        /// Интерфейс маршрута IPv6 по умолчанию или nil, если маршрута нет.
        public let interface: String?
        public init(interface: String?) { self.interface = interface }
        /// Маршрут есть и идёт не через туннель.
        public var isLeak: Bool {
            guard let interface else { return false }
            return !interface.hasPrefix("utun")
        }
        public var description: String {
            guard let interface else { return "маршрута нет — утечки нет" }
            return isLeak ? "маршрут через \(interface) — УТЕЧКА" : "маршрут через туннель (\(interface))"
        }
    }

    public static func ipv6() -> IPv6Status {
        let result = Shell.run("/sbin/route", ["-n", "get", "-inet6", "default"])
        guard result.status == 0 else { return IPv6Status(interface: nil) }
        for line in result.stdout.split(separator: "\n") {
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            if trimmed.hasPrefix("interface:") {
                return IPv6Status(interface: trimmed.dropFirst("interface:".count).trimmingCharacters(in: .whitespaces))
            }
        }
        return IPv6Status(interface: nil)
    }

    public struct DNSStatus: Equatable {
        /// Серверы из основной (нескопированной) конфигурации.
        public let nameservers: [String]
        public init(nameservers: [String]) { self.nameservers = nameservers }
        /// Среди серверов есть адрес из домашней сети — запросы идут к роутеру, мимо туннеля.
        public var isLeak: Bool {
            nameservers.contains { GeoIP.isPrivate($0) && !$0.hasPrefix("198.18.") && !$0.hasPrefix("198.19.") }
        }
        public var description: String {
            if nameservers.isEmpty { return "системных серверов нет — DNS внутри туннеля" }
            return (isLeak ? "через роутер: " : "") + nameservers.joined(separator: ", ")
        }
    }

    /// `scutil --dns` выводит две секции: основную и «for scoped queries».
    /// Scoped-резолверы привязаны к интерфейсам и для обычных запросов не используются.
    public static func dns() -> DNSStatus {
        let result = Shell.run("/usr/sbin/scutil", ["--dns"])
        var servers: [String] = []
        for line in result.stdout.split(separator: "\n") {
            if line.hasPrefix("DNS configuration (for scoped queries)") { break }
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            guard trimmed.hasPrefix("nameserver["), let colon = trimmed.firstIndex(of: ":") else { continue }
            let address = trimmed[trimmed.index(after: colon)...].trimmingCharacters(in: .whitespaces)
            if !servers.contains(address) { servers.append(address) }
        }
        return DNSStatus(nameservers: servers)
    }

    /// Часовой пояс Mac. Сравнение со страной — только строчкой, без влияния на состояние.
    public static func timezone() -> String {
        TimeZone.current.identifier
    }
}

/// Проверка 6 из CHECKS.md: что видит сайт. Только вручную, только при поднятом туннеле,
/// собственным клиентом без cookie.
public enum ExitCheck {
    public struct Result: Equatable {
        public let host: String
        public let ip: String
        public let country: String?
        public init(host: String, ip: String, country: String?) {
            self.host = host; self.ip = ip; self.country = country
        }
    }

    public enum Failure: Error, CustomStringConvertible {
        case tunnelDown
        case network(String)
        case unreadable

        public var description: String {
            switch self {
            case .tunnelDown: return "туннель не поднят — сайт увидел бы домашний адрес, запрос не отправлен"
            case .network(let message): return "сеть: \(message)"
            case .unreadable: return "ответ не разобран"
            }
        }
    }

    /// Запрос идёт через `Network.framework`, а не `URLSession`, ради привязки к туннелю: даже если
    /// туннель упадёт в миллисекунду между проверкой «туннель поднят» и отправкой, запрос не уйдёт
    /// с домашнего адреса — он просто не уйдёт.
    ///
    /// Две страховки: системе разрешён только тип интерфейса `.other` (туннели; Wi-Fi, кабель и
    /// сотовая — нет), а после соединения проверяется, что путь действительно через `utun*`.
    /// Запретить `.wifi` напрямую нельзя: macOS считает, что туннель «едет» поверх Wi-Fi, и запрет
    /// закрывает и его (проверено 07.11.2026).
    ///
    /// Синхронно; для сторожа и CLI достаточно, время ограничено `timeout`.
    public static func run(
        host: String,
        tunnel: TunnelStatus = TunnelCheck.check(),
        timeout: TimeInterval = 10
    ) -> Swift.Result<Result, Failure> {
        guard tunnel.isUp else { return .failure(.tunnelDown) }
        guard !host.isEmpty, !host.contains("/") else { return .failure(.network("плохой хост")) }

        let parameters = NWParameters.tls
        parameters.requiredInterfaceType = .other
        let connection = NWConnection(host: NWEndpoint.Host(host), port: 443, using: parameters)

        // Всё состояние трогается только на этой очереди; поток-вызыватель ждёт семафор.
        let queue = DispatchQueue(label: "sonyx.exit-check")
        let done = DispatchSemaphore(value: 0)
        final class Box: @unchecked Sendable {
            var response = Data()
            var failure: Failure?
            var finished = false
        }
        let box = Box()
        func complete(_ failure: Failure?) {
            guard !box.finished else { return }
            box.finished = true
            box.failure = failure
            done.signal()
        }
        func receive() {
            connection.receive(minimumIncompleteLength: 1, maximumLength: 65536) { data, _, isComplete, error in
                if let data { box.response.append(data) }
                if let error { complete(.network(error.localizedDescription)); return }
                if isComplete { complete(nil); return }
                receive()
            }
        }
        connection.stateUpdateHandler = { state in
            switch state {
            case .ready:
                let interfaces = connection.currentPath?.availableInterfaces.map(\.name) ?? []
                guard !interfaces.isEmpty, interfaces.allSatisfy({ $0.hasPrefix("utun") }) else {
                    complete(.network("путь не через туннель (\(interfaces.joined(separator: ", "))) — запрос не отправлен"))
                    return
                }
                // HTTP/1.0: сервер ответит целиком и закроет соединение, без chunked-кодирования.
                let request = "GET /cdn-cgi/trace HTTP/1.0\r\nHost: \(host)\r\nUser-Agent: SonyX/0.1 (+exit-check)\r\nAccept: text/plain\r\n\r\n"
                connection.send(content: Data(request.utf8), completion: .contentProcessed { error in
                    if let error { complete(.network(error.localizedDescription)) }
                })
                receive()
            case .failed(let error):
                complete(.network(error.localizedDescription))
            case .waiting(let error):
                // Нет пути до хоста (например, остался только запрещённый интерфейс) — ждать нечего.
                complete(.network("нет разрешённого пути: \(error.localizedDescription)"))
            case .cancelled:
                complete(.network("отменено"))
            default:
                break
            }
        }
        connection.start(queue: queue)
        if done.wait(timeout: .now() + timeout) == .timedOut {
            queue.sync { complete(.network("время вышло (\(Int(timeout)) с)")) }
        }
        connection.cancel()
        // После cancel() обработчики больше не вызываются; читаем состояние через ту же очередь.
        let (response, failure) = queue.sync { (box.response, box.failure) }
        if let failure { return .failure(failure) }

        guard let text = String(data: response, encoding: .utf8),
              let headerEnd = text.range(of: "\r\n\r\n") else { return .failure(.unreadable) }
        let statusLine = text[..<headerEnd.lowerBound].split(separator: "\r\n").first ?? ""
        guard statusLine.split(separator: " ").dropFirst().first == "200" else {
            return .failure(.network("ответ сервера: \(statusLine)"))
        }
        var fields: [String: String] = [:]
        for line in text[headerEnd.upperBound...].split(separator: "\n") {
            guard let eq = line.firstIndex(of: "=") else { continue }
            fields[String(line[..<eq])] = String(line[line.index(after: eq)...])
        }
        guard let ip = fields["ip"], !ip.isEmpty else { return .failure(.unreadable) }
        let loc = fields["loc"].flatMap { $0.count == 2 ? $0 : nil }
        return .success(Result(host: host, ip: ip, country: loc))
    }
}
