import Darwin
import Foundation

/// Заморозка и разморозка процессов штатными сигналами STOP / CONT.
public enum Freezer {
    public struct Outcome {
        public var done: [pid_t] = []
        public var failed: [(pid: pid_t, error: String)] = []
    }

    /// Сначала родители, потом дети: замороженный родитель не породит новых процессов,
    /// пока мы обходим дерево.
    public static func freeze(_ pids: Set<pid_t>, processes: [ProcessEntry]) -> Outcome {
        send(SIGSTOP, to: ordered(pids, processes: processes, parentsFirst: true))
    }

    /// Сначала дети, потом родители: родитель, проснувшись, увидит детей уже живыми.
    public static func resume(_ pids: Set<pid_t>, processes: [ProcessEntry]) -> Outcome {
        send(SIGCONT, to: ordered(pids, processes: processes, parentsFirst: false))
    }

    private static func send(_ signal: Int32, to pids: [pid_t]) -> Outcome {
        var outcome = Outcome()
        for pid in pids {
            if kill(pid, signal) == 0 {
                outcome.done.append(pid)
            } else {
                // ESRCH — процесс уже завершился, это не ошибка.
                if errno != ESRCH {
                    outcome.failed.append((pid, String(cString: strerror(errno))))
                }
            }
        }
        return outcome
    }

    private static func ordered(_ pids: Set<pid_t>, processes: [ProcessEntry], parentsFirst: Bool) -> [pid_t] {
        let depth = depths(of: pids, processes: processes)
        let sorted = pids.sorted { (depth[$0] ?? 0, $0) < (depth[$1] ?? 0, $1) }
        return parentsFirst ? sorted : sorted.reversed()
    }

    /// Глубина процесса внутри набора: корни набора — 0, их дети — 1 и т.д.
    private static func depths(of pids: Set<pid_t>, processes: [ProcessEntry]) -> [pid_t: Int] {
        let ppid = Dictionary(uniqueKeysWithValues: processes.map { ($0.pid, $0.ppid) })
        var result: [pid_t: Int] = [:]
        for pid in pids {
            var d = 0
            var current = ppid[pid] ?? 0
            while current > 1, pids.contains(current) {
                d += 1
                current = ppid[current] ?? 0
            }
            result[pid] = d
        }
        return result
    }
}
