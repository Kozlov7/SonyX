import Foundation

/// Настройки пользователя: `~/Library/Application Support/SonyX/config.json`.
/// JSON вместо YAML: читается штатными средствами, без зависимостей.
public struct Config: Codable, Equatable {
    /// Во всех режимах туннель упал или IPv6 наружу — пауза. Режим решает только про страну и адрес.
    public enum Mode: String, Codable, CaseIterable {
        /// Пускать везде, кроме запрещённых стран: встроенный список стран, где Claude не работает,
        /// плюс чёрный список пользователя (`denied`). Работает без настройки.
        case light
        /// Пускать только в разрешённых странах (`allowed.countries`).
        case medium
        /// Пускать только через разрешённые адреса серверов (`allowed.ips`).
        case strict

        public var title: String {
            switch self {
            case .light: return "лёгкий"
            case .medium: return "средний"
            case .strict: return "жёсткий"
            }
        }

        public var summary: String {
            switch self {
            case .light: return "пауза только в запрещённых странах"
            case .medium: return "пауза везде, кроме разрешённых стран"
            case .strict: return "пауза везде, кроме разрешённых адресов сервера"
            }
        }

        /// Старое имя «normal» (до 07.11.2026) — это нынешний средний режим.
        public init?(name: String) {
            switch name.lowercased() {
            case "normal": self = .medium
            default:
                guard let mode = Mode(rawValue: name.lowercased()) else { return nil }
                self = mode
            }
        }

        public init(from decoder: Decoder) throws {
            let raw = try decoder.singleValueContainer().decode(String.self)
            guard let mode = Mode(name: raw) else {
                throw DecodingError.dataCorruptedError(in: try decoder.singleValueContainer(),
                                                       debugDescription: "неизвестный режим «\(raw)», допустимы light, medium, strict")
            }
            self = mode
        }
    }

    public struct Allowed: Codable, Equatable {
        public var countries: [String] = []
        public var ips: [String] = []
        public init() {}
    }

    /// Чёрный список для лёгкого режима — вдобавок ко встроенному списку стран, где сервис не работает.
    public struct Denied: Codable, Equatable {
        public var countries: [String] = []
        public init() {}
    }

    /// Что реально видит сайт для данного адреса сервера (результат проверки 6).
    public struct Exit: Codable, Equatable {
        public var ip: String
        public var country: String?
        public var checkedAt: Date

        public init(ip: String, country: String?, checkedAt: Date) {
            self.ip = ip
            self.country = country
            self.checkedAt = checkedAt
        }
    }

    public var mode: Mode = .light
    public var allowed = Allowed()
    public var denied = Denied()
    /// Адрес сервера → что видит сайт.
    public var exits: [String: Exit] = [:]
    /// Хост для проверки «Что видит сайт».
    public var traceHost: String = "claude.ai"
    /// Сторож сам проверяет выход: при новом сервере, при переподключении и раз в `recheckMinutes`.
    public var autoCheck: Bool = true
    /// Плановая перепроверка выхода, минуты. 0 — только при новом сервере и переподключении.
    public var recheckMinutes: Int = 30

    public init() {}

    /// Каждое поле читается отдельно и при отсутствии берётся по умолчанию: файл, записанный
    /// старой версией, не должен ломаться из-за нового поля.
    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        mode = try c.decodeIfPresent(Mode.self, forKey: .mode) ?? .light
        allowed = try c.decodeIfPresent(Allowed.self, forKey: .allowed) ?? Allowed()
        denied = try c.decodeIfPresent(Denied.self, forKey: .denied) ?? Denied()
        exits = try c.decodeIfPresent([String: Exit].self, forKey: .exits) ?? [:]
        traceHost = try c.decodeIfPresent(String.self, forKey: .traceHost) ?? "claude.ai"
        autoCheck = try c.decodeIfPresent(Bool.self, forKey: .autoCheck) ?? true
        recheckMinutes = try c.decodeIfPresent(Int.self, forKey: .recheckMinutes) ?? 30
    }

    public static let file = StateStore.directory.appendingPathComponent("config.json")

    /// Результат чтения файла настроек.
    ///
    /// Если файла нет — это первый запуск, `config` пустой, `error == nil`.
    /// Если файл есть, но не читается (например, лишняя запятая после ручной правки) —
    /// `config` тоже пустой, но `error` объясняет почему. Сохранять поверх такого файла
    /// нельзя: это стёрло бы настройки пользователя без предупреждения.
    public struct Loaded {
        public var config: Config
        public var error: String?

        public init(config: Config, error: String? = nil) {
            self.config = config
            self.error = error
        }

        /// Можно ли записывать файл. При ошибке чтения — нет.
        public var isWritable: Bool { error == nil }
    }

    public static func load() -> Loaded {
        guard FileManager.default.fileExists(atPath: file.path) else { return Loaded(config: Config()) }
        let data: Data
        do {
            data = try Data(contentsOf: file)
        } catch {
            return Loaded(config: Config(), error: "файл \(file.path) не читается: \(error.localizedDescription)")
        }
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        do {
            return Loaded(config: try decoder.decode(Config.self, from: data))
        } catch {
            return Loaded(config: Config(), error: "файл \(file.path) повреждён — \(describe(error))")
        }
    }

    /// Понятное описание ошибки разбора JSON: где и что не так.
    private static func describe(_ error: Error) -> String {
        guard let decoding = error as? DecodingError else { return error.localizedDescription }
        func path(_ context: DecodingError.Context) -> String {
            context.codingPath.map(\.stringValue).joined(separator: ".")
        }
        switch decoding {
        case .dataCorrupted(let context):
            // У ошибки JSON-разборщика внутри лежит строка вида «Unexpected character ',' around line 5, column 3.»
            let detail = (context.underlyingError as NSError?)?.userInfo[NSDebugDescriptionErrorKey] as? String
            return "неверный JSON" + (detail.map { ": \($0)" } ?? "") + (path(context).isEmpty ? "" : " (поле \(path(context)))")
        case .keyNotFound(let key, let context):
            return "нет обязательного поля \(([path(context), key.stringValue].filter { !$0.isEmpty }).joined(separator: "."))"
        case .typeMismatch(_, let context):
            return "поле \(path(context)) имеет неверный тип"
        case .valueNotFound(_, let context):
            return "поле \(path(context)) пустое"
        @unknown default:
            return error.localizedDescription
        }
    }

    public func save() {
        try? FileManager.default.createDirectory(at: StateStore.directory, withIntermediateDirectories: true)
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        if let data = try? encoder.encode(self) {
            try? data.write(to: Config.file, options: .atomic)
        }
    }

    public var isLearned: Bool { !allowed.countries.isEmpty || !allowed.ips.isEmpty }

    public mutating func allow(country: String) {
        let code = country.uppercased()
        if !allowed.countries.contains(code) { allowed.countries.append(code) }
    }

    public mutating func allow(ip: String) {
        if !allowed.ips.contains(ip) { allowed.ips.append(ip) }
    }

    /// Возвращает false, если такого и не было.
    @discardableResult
    public mutating func disallow(country: String) -> Bool {
        let before = allowed.countries.count
        allowed.countries.removeAll { $0 == country.uppercased() }
        return allowed.countries.count != before
    }

    @discardableResult
    public mutating func disallow(ip: String) -> Bool {
        let before = allowed.ips.count
        allowed.ips.removeAll { $0 == ip }
        return allowed.ips.count != before
    }

    public mutating func deny(country: String) {
        let code = country.uppercased()
        if !denied.countries.contains(code) { denied.countries.append(code) }
    }

    @discardableResult
    public mutating func undeny(country: String) -> Bool {
        let before = denied.countries.count
        denied.countries.removeAll { $0 == country.uppercased() }
        return denied.countries.count != before
    }

    /// Запрещена ли страна в лёгком режиме и почему.
    public func denialReason(country: String) -> String? {
        if denied.countries.contains(country) { return "она в вашем чёрном списке" }
        if ServiceRegions.status(of: .claude, country: country) == .unsupported { return "там Claude официально не работает" }
        return nil
    }
}

/// Страна, по которой принимается решение, и откуда она известна.
///
/// Сервер, к которому подключён VPN-клиент, и адрес, с которого трафик выходит к сайту,
/// могут быть в разных странах (цепочка серверов). Сайт видит второй. Поэтому если для
/// сервера уже известен выход (проверка 6, `sonyx exit-check`), решение принимается по нему,
/// и только иначе — по базе GeoIP для адреса сервера.
public struct CountryInfo: Equatable {
    public enum Source: Equatable {
        /// Результат проверки «что видит сайт» для этого сервера.
        case exitCheck(Date)
        /// Локальная база GeoIP по адресу сервера.
        case database
    }

    public let code: String?
    public let source: Source

    public static func resolve(server: String, config: Config, geo: GeoIP?) -> CountryInfo {
        if let exit = config.exits[server], let code = exit.country {
            return CountryInfo(code: code, source: .exitCheck(exit.checkedAt))
        }
        return CountryInfo(code: geo?.country(of: server), source: .database)
    }

    /// «по проверке выхода 06.11 18:53» или «по базе».
    public var sourceDescription: String {
        switch source {
        case .exitCheck(let date):
            let formatter = DateFormatter()
            formatter.dateFormat = "dd.MM HH:mm"
            return "по проверке выхода \(formatter.string(from: date))"
        case .database:
            return "по базе"
        }
    }

    /// Выход для этого сервера ещё не проверялся — страна по базе может не совпадать с настоящей.
    public var isExitUnknown: Bool { source == .database }
}

/// Решение по текущему состоянию.
public enum Verdict: Equatable {
    case ok
    /// Пауза с причиной для журнала и подсказкой пользователю.
    case pause(reason: String, hint: String?)
    /// Первое включение: адрес и страну надо запомнить.
    case learn(ip: String, country: String?)
}

public enum Policy {
    /// `tunnel` — проверка 1, `ipv6Leak` — проверка 3, `server` — проверка 2.
    public static func evaluate(
        tunnel: TunnelStatus,
        ipv6Leak: Bool,
        server: ServerDetector.Candidate?,
        config: Config,
        geo: GeoIP?
    ) -> Verdict {
        guard tunnel.isUp else {
            return .pause(reason: tunnel.description, hint: nil)
        }
        if ipv6Leak {
            return .pause(reason: "IPv6 идёт мимо туннеля", hint: "выключите IPv6: networksetup -setv6off Wi-Fi")
        }
        // Сервер ещё не виден (туннель простаивает) — опираемся на проверку туннеля.
        guard let server else { return .ok }

        let info = CountryInfo.resolve(server: server.address, config: config, geo: geo)
        let country = info.code
        if !config.isLearned {
            return .learn(ip: server.address, country: country)
        }

        let place = country.map { "\(countryName($0)) (\(info.sourceDescription))" } ?? "страна неизвестна"
        // Пока выход не проверен, страна по базе — лишь предположение: сервер может быть
        // промежуточным. Разрешать или запрещать по ней вслепую не предлагаем — сначала проверка 6.
        let checkFirst = "сначала sonyx exit-check — покажет настоящую страну выхода"

        switch config.mode {
        case .light:
            guard let country, let why = config.denialReason(country: country) else { return .ok }
            let hint = info.isExitUnknown
                ? "\(checkFirst); если она разрешена — пауза снимется сама"
                : (config.denied.countries.contains(country) ? "sonyx undeny country \(country)  или смените сервер в VPN-клиенте" : "смените сервер в VPN-клиенте")
            return .pause(reason: "сервер \(server.address), \(place) — \(why)", hint: hint)

        case .medium:
            guard let country else {
                return .pause(reason: "сервер \(server.address), страна неизвестна — средний режим пускает только в разрешённые",
                              hint: "\(checkFirst); затем sonyx allow country <страна выхода>")
            }
            guard config.allowed.countries.contains(country) else {
                let hint = info.isExitUnknown
                    ? "\(checkFirst); затем sonyx allow country <страна выхода>"
                    : "sonyx allow country \(country)"
                return .pause(reason: "сервер \(server.address), \(place) — она не разрешена", hint: hint)
            }
            return .ok

        case .strict:
            guard config.allowed.ips.contains(server.address) else {
                return .pause(reason: "новый сервер \(server.address), \(place) — жёсткий режим пускает только через разрешённые адреса",
                              hint: "sonyx allow ip \(server.address)" + (info.isExitUnknown ? "  (\(checkFirst))" : ""))
            }
            return .ok
        }
    }
}
