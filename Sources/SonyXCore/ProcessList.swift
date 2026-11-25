import Darwin
import Foundation

/// Один процесс из списка системы.
public struct ProcessEntry: Hashable {
    public let pid: pid_t
    public let ppid: pid_t
    public let uid: uid_t
    public let path: String
    /// Процесс остановлен сигналом STOP (состояние SSTOP).
    public let isStopped: Bool

    public var name: String { (path as NSString).lastPathComponent }
}

public enum ProcessList {
    /// Полный список процессов через sysctl, без запуска `ps`.
    public static func all() -> [ProcessEntry] {
        var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_ALL, 0]
        var size = 0
        guard sysctl(&mib, 4, nil, &size, nil, 0) == 0, size > 0 else { return [] }

        let stride = MemoryLayout<kinfo_proc>.stride
        // Запас на процессы, появившиеся между двумя вызовами.
        var buffer = [kinfo_proc](repeating: kinfo_proc(), count: size / stride + 32)
        size = buffer.count * stride
        guard sysctl(&mib, 4, &buffer, &size, nil, 0) == 0 else { return [] }

        let count = size / stride
        var result: [ProcessEntry] = []
        result.reserveCapacity(count)
        for i in 0..<count {
            let kp = buffer[i]
            let pid = kp.kp_proc.p_pid
            guard pid > 0 else { continue }
            result.append(ProcessEntry(
                pid: pid,
                ppid: kp.kp_eproc.e_ppid,
                uid: kp.kp_eproc.e_ucred.cr_uid,
                path: path(of: pid),
                isStopped: kp.kp_proc.p_stat == SSTOP
            ))
        }
        return result
    }

    /// Полный путь к исполняемому файлу процесса. Пустая строка, если недоступен
    /// (чужие или системные процессы).
    public static func path(of pid: pid_t) -> String {
        // PROC_PIDPATHINFO_MAXSIZE = 4 * MAXPATHLEN; сам макрос в Swift не импортируется.
        var buffer = [CChar](repeating: 0, count: 4 * Int(MAXPATHLEN))
        let length = proc_pidpath(pid, &buffer, UInt32(buffer.count))
        guard length > 0 else { return "" }
        return String(cString: buffer)
    }

    /// Все предки процесса (родитель, его родитель и т.д.).
    public static func ancestors(of pid: pid_t, in processes: [ProcessEntry]) -> Set<pid_t> {
        let byPid = Dictionary(uniqueKeysWithValues: processes.map { ($0.pid, $0) })
        var result = Set<pid_t>()
        var current = byPid[pid]?.ppid ?? 0
        while current > 1, !result.contains(current), let entry = byPid[current] {
            result.insert(current)
            current = entry.ppid
        }
        return result
    }

    /// Все потомки процессов из `roots`, включая сами корни.
    public static func subtree(of roots: Set<pid_t>, in processes: [ProcessEntry]) -> Set<pid_t> {
        var children: [pid_t: [pid_t]] = [:]
        for entry in processes {
            children[entry.ppid, default: []].append(entry.pid)
        }
        var result = Set<pid_t>()
        var queue = Array(roots)
        while let pid = queue.popLast() {
            guard result.insert(pid).inserted else { continue }
            queue.append(contentsOf: children[pid] ?? [])
        }
        return result
    }
}
