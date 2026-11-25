import Foundation

/// Память о состоянии между запусками (ARCHITECTURE.md, «Память о состоянии»).
public struct State: Codable, Equatable {
    public struct Frozen: Codable, Equatable {
        public let pid: pid_t
        public let path: String
        public let since: Date
    }

    public var frozen: [Frozen] = []
    public var lastTunnelInterface: String?
    public var updatedAt: Date = Date()

    public init() {}
}

public enum StateStore {
    public static let directory: URL = {
        let base = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
        return base.appendingPathComponent("SonyX", isDirectory: true)
    }()

    public static let stateFile = directory.appendingPathComponent("state.json")
    public static let logFile = directory.appendingPathComponent("sonyx.log")

    public static func load() -> State {
        guard let data = try? Data(contentsOf: stateFile) else { return State() }
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        return (try? decoder.decode(State.self, from: data)) ?? State()
    }

    public static func save(_ state: State) {
        var state = state
        state.updatedAt = Date()
        try? FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        if let data = try? encoder.encode(state) {
            try? data.write(to: stateFile, options: .atomic)
        }
    }

    /// Процессы из прошлого запуска, которые всё ещё существуют, остановлены
    /// и остались той же программой (pid мог достаться другому процессу).
    public static func stillFrozen(_ state: State, in processes: [ProcessEntry]) -> Set<pid_t> {
        let byPid = Dictionary(uniqueKeysWithValues: processes.map { ($0.pid, $0) })
        return Set(state.frozen.compactMap { record in
            guard let entry = byPid[record.pid], entry.isStopped, entry.path == record.path else { return nil }
            return record.pid
        })
    }
}
