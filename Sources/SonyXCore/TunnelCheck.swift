import Foundation

/// Проверка 1 из CHECKS.md: идёт ли маршрут по умолчанию через туннель.
public struct TunnelStatus: Equatable {
    /// Интерфейс маршрута по умолчанию (`utun78`, `en0`…) или nil, если маршрута нет.
    public let interface: String?
    /// Команда `route` не ответила вовремя: состояние неизвестно. Это не «туннель упал»:
    /// сторож в таком случае считает состояние прежним (см. `Guardian.tick`).
    public let isUnknown: Bool

    public init(interface: String?, isUnknown: Bool = false) {
        self.interface = interface
        self.isUnknown = isUnknown
    }

    public static let unknown = TunnelStatus(interface: nil, isUnknown: true)

    /// Туннель поднят, если маршрут по умолчанию идёт через любой `utun*`.
    public var isUp: Bool {
        guard let interface else { return false }
        return interface.hasPrefix("utun")
    }

    public var description: String {
        if isUnknown { return "состояние туннеля неизвестно — route не ответил" }
        guard let interface else { return "маршрута по умолчанию нет" }
        return isUp ? "туннель поднят (\(interface))" : "трафик идёт напрямую (\(interface))"
    }
}

public enum TunnelCheck {
    public static let timeout: TimeInterval = 3

    public static func check() -> TunnelStatus {
        let result = Shell.run("/sbin/route", ["-n", "get", "default"], timeout: timeout)
        if result.timedOut { return .unknown }
        // При отсутствии маршрута route пишет "not in table" и выходит с ошибкой.
        guard result.status == 0 else { return TunnelStatus(interface: nil) }
        for line in result.stdout.split(separator: "\n") {
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            if trimmed.hasPrefix("interface:") {
                let name = trimmed.dropFirst("interface:".count).trimmingCharacters(in: .whitespaces)
                return TunnelStatus(interface: name.isEmpty ? nil : name)
            }
        }
        return TunnelStatus(interface: nil)
    }
}
