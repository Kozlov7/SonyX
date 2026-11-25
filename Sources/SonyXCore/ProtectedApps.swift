import Foundation

/// Описание защищаемой программы и правило, по которому ищутся её процессы.
public struct ProtectedApp: Equatable {
    public enum Rule: Equatable {
        /// Все процессы внутри бандла с таким именем: `Google Chrome.app`.
        /// Ищется как `/Google Chrome.app/` в любом месте пути, поэтому программа может
        /// лежать и в `/Applications`, и в `~/Applications`. «Google Chrome Canary.app» не совпадёт.
        case bundle(String)
        /// Процесс с таким именем исполняемого файла (`claude`).
        case executableName(String)
    }

    public let name: String
    public let rule: Rule

    public init(name: String, rule: Rule) {
        self.name = name
        self.rule = rule
    }

    public func matches(_ entry: ProcessEntry) -> Bool {
        switch rule {
        case .bundle(let bundleName):
            return entry.path.contains("/" + bundleName + "/")
        case .executableName(let name):
            return entry.name == name
        }
    }

    /// Список по умолчанию из README.md.
    public static let defaults: [ProtectedApp] = [
        ProtectedApp(name: "Google Chrome", rule: .bundle("Google Chrome.app")),
        ProtectedApp(name: "Cursor", rule: .bundle("Cursor.app")),
        ProtectedApp(name: "Claude Code", rule: .executableName("claude")),
    ]
}

/// Найденные процессы одной защищаемой программы.
public struct AppProcesses {
    public let app: ProtectedApp
    public let pids: Set<pid_t>
    public let frozenCount: Int
}

public enum Matcher {
    /// Для каждой программы — все её процессы вместе с потомками.
    /// Сам SonyX и его предки (терминал, из которого он запущен) исключаются:
    /// иначе, запущенный из Cursor, он заморозил бы сам себя и не смог бы ничего отпустить.
    public static func find(
        apps: [ProtectedApp],
        in processes: [ProcessEntry],
        excluding selfPid: pid_t = getpid()
    ) -> [AppProcesses] {
        let me = ProcessList.ancestors(of: selfPid, in: processes).union([selfPid])
        let uid = getuid()
        let byPid = Dictionary(uniqueKeysWithValues: processes.map { ($0.pid, $0) })

        return apps.map { app in
            let roots = Set(processes.filter { app.matches($0) }.map(\.pid))
            let tree = ProcessList.subtree(of: roots, in: processes)
                .subtracting(me)
                // Чужие процессы заморозить всё равно не выйдет.
                .filter { byPid[$0]?.uid == uid }
            let frozen = tree.filter { byPid[$0]?.isStopped == true }.count
            return AppProcesses(app: app, pids: tree, frozenCount: frozen)
        }
    }
}
