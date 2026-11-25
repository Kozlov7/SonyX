import Darwin
import Foundation

/// Запуск системной команды с захватом вывода.
///
/// Две защиты от зависания сторожа (все проверки идут в одном потоке, и повисшая команда
/// остановила бы и заморозку, и Ctrl-C):
/// - оба вывода (обычный и ошибок) читаются одновременно. Если читать по очереди, команда,
///   написавшая много в stderr, встанет на заполненном буфере и будет ждать нас, а мы — её;
/// - ожидание ограничено `timeout`: команду, не ответившую вовремя, убиваем.
enum Shell {
    struct Result {
        let status: Int32
        let stdout: String
        let stderr: String
        /// Команда не уложилась в срок и была убита; `stdout`/`stderr` — что успело прийти.
        let timedOut: Bool
    }

    static let defaultTimeout: TimeInterval = 5

    static func run(_ path: String, _ args: [String], timeout: TimeInterval = defaultTimeout) -> Result {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: path)
        process.arguments = args
        let out = Pipe()
        let err = Pipe()
        process.standardOutput = out
        process.standardError = err

        let exited = DispatchSemaphore(value: 0)
        process.terminationHandler = { _ in exited.signal() }

        do {
            try process.run()
        } catch {
            return Result(status: -1, stdout: "", stderr: "\(error)", timedOut: false)
        }

        // Читаем оба вывода параллельно, в фоновых потоках.
        let readers = DispatchGroup()
        let outBox = DataBox(), errBox = DataBox()
        for (handle, box) in [(out.fileHandleForReading, outBox), (err.fileHandleForReading, errBox)] {
            readers.enter()
            DispatchQueue.global(qos: .userInitiated).async {
                box.data = handle.readDataToEndOfFile()
                readers.leave()
            }
        }

        var timedOut = false
        if exited.wait(timeout: .now() + timeout) == .timedOut {
            timedOut = true
            process.terminate()
            if exited.wait(timeout: .now() + 1) == .timedOut {
                kill(process.processIdentifier, SIGKILL)
                exited.wait()
            }
        }
        // После завершения команды её концы труб закрываются и чтение заканчивается само.
        // Страховка на случай, если команда успела породить потомка, который держит трубу.
        _ = readers.wait(timeout: .now() + 1)

        return Result(
            status: timedOut ? -1 : process.terminationStatus,
            stdout: String(decoding: outBox.data, as: UTF8.self),
            stderr: String(decoding: errBox.data, as: UTF8.self),
            timedOut: timedOut
        )
    }

    /// Контейнер для данных, которые заполняет фоновый поток.
    private final class DataBox: @unchecked Sendable {
        var data = Data()
    }
}
