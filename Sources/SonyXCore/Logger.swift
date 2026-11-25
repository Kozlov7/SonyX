import Foundation

/// Число с правильной формой слова: «1 процесс», «3 процесса», «43 процесса», «45 процессов».
/// `forms` — именительный единственного, родительный единственного, родительный множественного.
public func plural(_ count: Int, _ forms: (String, String, String)) -> String {
    let n = abs(count)
    let word: String
    if n % 10 == 1, n % 100 != 11 {
        word = forms.0
    } else if (2...4).contains(n % 10), !(12...14).contains(n % 100) {
        word = forms.1
    } else {
        word = forms.2
    }
    return "\(count) \(word)"
}

public enum Words {
    public static let processes = ("процесс", "процесса", "процессов")
    public static let connections = ("соединение", "соединения", "соединений")
}

/// Журнал событий: в файл и, если включено, в терминал.
public final class Logger {
    public var echoToConsole: Bool
    private let file: URL
    private let formatter: DateFormatter

    public init(file: URL = StateStore.logFile, echoToConsole: Bool = true) {
        self.file = file
        self.echoToConsole = echoToConsole
        formatter = DateFormatter()
        formatter.dateFormat = "yyyy-MM-dd HH:mm:ss.SSS"
        formatter.locale = Locale(identifier: "ru_RU")
    }

    public func log(_ message: String) {
        let line = "\(formatter.string(from: Date()))  \(message)\n"
        if echoToConsole {
            FileHandle.standardError.write(Data(line.utf8))
        }
        try? FileManager.default.createDirectory(at: file.deletingLastPathComponent(), withIntermediateDirectories: true)
        if let handle = try? FileHandle(forWritingTo: file) {
            handle.seekToEndOfFile()
            handle.write(Data(line.utf8))
            try? handle.close()
        } else {
            try? Data(line.utf8).write(to: file)
        }
    }
}
