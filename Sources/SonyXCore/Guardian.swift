import Foundation

/// Ядро сторожа: один `tick()` — одна проверка и реакция.
public final class Guardian {
    public let apps: [ProtectedApp]
    public let dryRun: Bool
    private let logger: Logger
    private let geo: GeoIP?
    private let detector = ServerDetector()

    /// Источники данных. Подменяются в тестах.
    public struct Sources {
        public var tunnel: () -> TunnelStatus = TunnelCheck.check
        public var ipv6: () -> Diagnostics.IPv6Status = Diagnostics.ipv6
        public var dns: () -> Diagnostics.DNSStatus = Diagnostics.dns
        public var connections: () -> [Connection] = Connections.established
        public var config: () -> Config.Loaded = Config.load
        public var saveConfig: (Config) -> Void = { $0.save() }
        /// Проверка 6 «что видит сайт»: хост, состояние туннеля → результат.
        public var exitCheck: (String, TunnelStatus) -> Result<ExitCheck.Result, ExitCheck.Failure> = {
            ExitCheck.run(host: $0, tunnel: $1, timeout: Guardian.exitCheckTimeout)
        }
        public var now: () -> Date = Date.init
        public init() {}
    }

    /// Проверка выхода идёт в том же потоке, что и всё остальное, поэтому время ограничено.
    public static let exitCheckTimeout: TimeInterval = 5
    /// После неудачной проверки выхода следующая попытка не раньше чем через столько секунд.
    public static let exitCheckRetry: TimeInterval = 60
    private var sources: Sources

    /// PID, которые заморозили мы (а не пользователь через Ctrl-Z).
    public private(set) var frozen: [pid_t: State.Frozen] = [:]
    public private(set) var lastTunnel: TunnelStatus?
    public private(set) var lastVerdict: Verdict?
    private var lastDNSLeak: Bool?
    /// Последняя ошибка чтения настроек, чтобы не писать её в журнал каждый опрос.
    private var lastConfigError: String?
    /// Прошлый опрос не смог узнать состояние туннеля (route не ответил).
    private var tunnelWasUnknown = false

    /// Последняя автопроверка выхода: для какого сервера и когда. Сбрасывается при падении
    /// туннеля и пробуждении — после них подключение считается новым.
    private var lastExitCheck: (server: String, at: Date)?
    /// После неудачи — не раньше этого момента.
    private var exitCheckNotBefore: Date?

    /// Снимок последней проверки для `sonyx status` и окна.
    public struct Snapshot {
        public var tunnel: TunnelStatus
        public var ipv6: Diagnostics.IPv6Status
        public var dns: Diagnostics.DNSStatus
        public var server: ServerDetector.Candidate?
        public var serverCountry: String?
        public var exit: Config.Exit?
        public var verdict: Verdict
        public var mode: Config.Mode
    }
    public private(set) var snapshot: Snapshot?

    public init(
        apps: [ProtectedApp] = ProtectedApp.defaults,
        dryRun: Bool = false,
        logger: Logger,
        geo: GeoIP? = GeoIP.shared,
        sources: Sources = Sources()
    ) {
        self.apps = apps
        self.dryRun = dryRun
        self.logger = logger
        self.geo = geo
        self.sources = sources
    }

    // MARK: - Сон и выдержка

    /// До этого момента «всё в порядке» не считается поводом отпускать: сразу после
    /// пробуждения таблица маршрутов может ещё показывать старый туннель.
    private var holdUntil: Date?
    public static let wakeHold: TimeInterval = 3

    /// Между «засыпаю» и «проснулся» отпускать нельзя вовсе: Mac засыпает не мгновенно,
    /// и опрос за эти секунды увидит «туннель поднят». Считаем по времени бодрствования
    /// (`systemUptime` во сне не идёт): если «проснулся» так и не пришёл — сон отменили,
    /// через минуту снимаем запрет сами.
    private var sleepingSince: TimeInterval?
    public static let sleepHoldFallback: TimeInterval = 60

    private var isHolding: Bool {
        if let sleepingSince {
            if ProcessInfo.processInfo.systemUptime - sleepingSince < Self.sleepHoldFallback { return true }
            self.sleepingSince = nil
            logger.log("«Проснулся» не пришёл за \(Int(Self.sleepHoldFallback)) с бодрствования — считаю, что сон отменён")
        }
        if let holdUntil {
            if Date() < holdUntil { return true }
            self.holdUntil = nil
        }
        return false
    }

    public func willSleep() {
        sleepingSince = ProcessInfo.processInfo.systemUptime
        freezeAll(reason: "Mac засыпает")
    }

    public func didWake() {
        // macOS шлёт два сообщения о пробуждении подряд (WillPowerOn и HasPoweredOn);
        // второе только продлевает выдержку, без повторной записи в журнал.
        let repeated = sleepingSince == nil && holdUntil.map { Date() < $0 } == true
        sleepingSince = nil
        holdUntil = Date().addingTimeInterval(Self.wakeHold)
        detector.reset()
        lastExitCheck = nil
        guard !repeated else { return }
        logger.log("Mac проснулся — проверяю, выдержка \(Int(Self.wakeHold)) с")
        tick(trigger: "пробуждение")
    }

    /// Пока что-то заморожено, есть проблема или идёт выдержка после сна, опрашивать
    /// надо чаще: новые процессы защищаемых программ должны замораживаться быстро.
    public var wantsFastPolling: Bool {
        if !frozen.isEmpty || holdUntil != nil || sleepingSince != nil { return true }
        if case .pause = lastVerdict { return true }
        return lastVerdict == nil
    }

    // MARK: - Запуск

    public func warnIfLaunchedFromProtectedApp(processes: [ProcessEntry]) {
        let ancestors = ProcessList.ancestors(of: getpid(), in: processes)
        let byPid = Dictionary(uniqueKeysWithValues: processes.map { ($0.pid, $0) })
        for app in apps where ancestors.contains(where: { byPid[$0].map(app.matches) == true }) {
            logger.log("ВНИМАНИЕ: SonyX запущен из-под \(app.name) — \(app.name) не будет заморожен. Запустите из Terminal.app")
        }
    }

    /// Подхватить процессы, замороженные прошлым запуском SonyX.
    public func restore(from state: State, processes: [ProcessEntry]) {
        let alive = StateStore.stillFrozen(state, in: processes)
        guard !alive.isEmpty else { return }
        let byPid = Dictionary(uniqueKeysWithValues: processes.map { ($0.pid, $0) })
        for pid in alive {
            frozen[pid] = State.Frozen(pid: pid, path: byPid[pid]?.path ?? "", since: state.updatedAt)
        }
        logger.log("С прошлого запуска всё ещё заморожено: \(plural(alive.count, Words.processes)) — беру под контроль")
    }

    // MARK: - Проверка

    /// `trigger` — что вызвало проверку: «опрос», «событие сети», «пробуждение». Только для журнала.
    public func tick(trigger: String = "опрос") {
        var tunnel = sources.tunnel()
        if tunnel.isUnknown {
            // route не ответил. Это не повод ни морозить, ни отпускать: оставляем прошлое
            // состояние. Если прошлого нет (первая проверка) — isUp == false, то есть пауза:
            // при сомнении безопаснее стоять.
            if !tunnelWasUnknown {
                logger.log("route не ответил за \(Int(TunnelCheck.timeout)) с — считаю состояние туннеля прежним\(lastTunnel.map { " (\($0.description))" } ?? "")")
            }
            tunnelWasUnknown = true
            if let lastTunnel { tunnel = lastTunnel }
        } else if tunnelWasUnknown {
            tunnelWasUnknown = false
            logger.log("route снова отвечает: \(tunnel.description)")
        }
        let ipv6 = sources.ipv6()
        let dns = sources.dns()
        let loaded = sources.config()
        var config = loaded.config

        if loaded.error != lastConfigError {
            if let error = loaded.error {
                logger.log("ОШИБКА НАСТРОЕК: \(error)")
                logger.log("  Ничего не сохраняю, чтобы не стереть ваши настройки. Пока файл не исправлен, проверяется только туннель и IPv6, страна сервера — нет")
            } else if lastConfigError != nil {
                logger.log("Файл настроек снова читается")
            }
            lastConfigError = loaded.error
        }

        if tunnel.isUp {
            detector.update(with: sources.connections())
        } else {
            // После переподключения клиент может выбрать другой сервер.
            detector.reset()
            lastExitCheck = nil
        }
        let server = detector.current

        // Автопроверка выхода — до решения, чтобы решать уже по настоящей стране.
        if tunnel.isUp, let server, config.autoCheck, loaded.isWritable,
           let why = exitCheckReason(server: server.address, config: config) {
            autoCheckExit(server: server.address, why: why, tunnel: tunnel, config: &config)
        }

        // Страна, по которой принимается решение: известный выход важнее базы (см. CountryInfo).
        let countryInfo = server.map { CountryInfo.resolve(server: $0.address, config: config, geo: geo) }
        let serverCountry = countryInfo?.code

        var verdict = Policy.evaluate(tunnel: tunnel, ipv6Leak: ipv6.isLeak, server: server, config: config, geo: geo)
        if case .learn(let ip, let country) = verdict {
            // При повреждённом файле «первый запуск» — иллюзия: настройки есть, просто не читаются.
            // Записывать поверх них нельзя.
            if loaded.isWritable {
                config.allow(ip: ip)
                if let country { config.allow(country: country) }
                sources.saveConfig(config)
                logger.log("Защита включена: запомнил сервер \(ip)\(country.map { " (\(countryName($0)))" } ?? ""). Сменить разрешённые: sonyx allow …")
            }
            verdict = .ok
        }

        let processes = ProcessList.all()
        let byPid = Dictionary(uniqueKeysWithValues: processes.map { ($0.pid, $0) })
        frozen = frozen.filter { byPid[$0.key] != nil }
        let found = Matcher.find(apps: apps, in: processes)
        let protected = found.reduce(into: Set<pid_t>()) { $0.formUnion($1.pids) }

        switch verdict {
        case .pause(let reason, let hint):
            let toFreeze = protected.subtracting(frozen.keys).filter { byPid[$0]?.isStopped == false }
            if !toFreeze.isEmpty {
                let outcome = dryRun ? Freezer.Outcome(done: Array(toFreeze)) : Freezer.freeze(toFreeze, processes: processes)
                let now = Date()
                for pid in outcome.done {
                    frozen[pid] = State.Frozen(pid: pid, path: byPid[pid]?.path ?? "", since: now)
                }
                let names = found.filter { !$0.pids.isDisjoint(with: toFreeze) }.map(\.app.name).joined(separator: ", ")
                logger.log("\(reason) — заморожено \(plural(outcome.done.count, Words.processes)): \(names) [\(trigger)]\(dryRun ? " (пробный режим)" : "")")
                if let hint { logger.log("  чтобы разрешить: \(hint)") }
                report(outcome)
            } else if lastVerdict != verdict {
                logger.log("\(reason) — защищаемые программы не запущены или уже стоят [\(trigger)]")
                if let hint { logger.log("  чтобы разрешить: \(hint)") }
            }
        case .ok:
            if isHolding {
                // Всё вроде в порядке, но Mac засыпает или только что проснулся — рано верить.
            } else if !frozen.isEmpty {
                let pids = Set(frozen.keys)
                let outcome = dryRun ? Freezer.Outcome(done: Array(pids)) : Freezer.resume(pids, processes: processes)
                logger.log("\(describeOK(tunnel, server, countryInfo)) — отпускаю \(plural(outcome.done.count, Words.processes)) [\(trigger)]\(dryRun ? " (пробный режим)" : "")")
                report(outcome)
                frozen = [:]
            }
        case .learn:
            break
        }

        if lastTunnel != tunnel {
            if let previous = lastTunnel {
                logger.log("Сеть: \(previous.description) → \(tunnel.description)")
            }
            lastTunnel = tunnel
        }
        if tunnel.isUp, lastDNSLeak != dns.isLeak {
            if dns.isLeak {
                logger.log("Предупреждение: DNS \(dns.description) — провайдер видит имена сайтов")
            } else if lastDNSLeak == true {
                logger.log("DNS снова в порядке: \(dns.description)")
            }
            lastDNSLeak = dns.isLeak
        }
        lastVerdict = verdict

        snapshot = Snapshot(
            tunnel: tunnel, ipv6: ipv6, dns: dns, server: server, serverCountry: serverCountry,
            exit: server.flatMap { config.exits[$0.address] }, verdict: verdict, mode: config.mode
        )
        persist(tunnel)
    }

    // MARK: - Автопроверка выхода

    /// Нужна ли сейчас проверка выхода и почему. nil — не нужна.
    func exitCheckReason(server: String, config: Config) -> String? {
        let now = sources.now()
        if let notBefore = exitCheckNotBefore, now < notBefore { return nil }
        if config.exits[server] == nil { return "новый сервер" }
        guard let last = lastExitCheck else { return "подключение" }
        if last.server != server { return "смена сервера" }
        if config.recheckMinutes > 0, now.timeIntervalSince(last.at) >= TimeInterval(config.recheckMinutes * 60) {
            return "плановая перепроверка раз в \(config.recheckMinutes) мин"
        }
        return nil
    }

    private func autoCheckExit(server: String, why: String, tunnel: TunnelStatus, config: inout Config) {
        let now = sources.now()
        switch sources.exitCheck(config.traceHost, tunnel) {
        case .success(let result):
            lastExitCheck = (server, now)
            exitCheckNotBefore = nil
            let previous = config.exits[server]
            config.exits[server] = Config.Exit(ip: result.ip, country: result.country, checkedAt: now)
            sources.saveConfig(config)
            let place = "\(result.ip)\(result.country.map { " (\(countryName($0)))" } ?? "")"
            if let previous, previous.ip != result.ip || previous.country != result.country {
                let was = "\(previous.ip)\(previous.country.map { " (\(countryName($0)))" } ?? "")"
                logger.log("Проверка выхода (\(why)): сервер \(server) → выход \(place). ИЗМЕНИЛСЯ: раньше был \(was)")
            } else {
                logger.log("Проверка выхода (\(why)): сервер \(server) → выход \(place)")
            }
        case .failure(let error):
            exitCheckNotBefore = now.addingTimeInterval(Self.exitCheckRetry)
            logger.log("Проверка выхода (\(why)) не удалась: \(error) — решаю по тому, что известно; повтор через \(Int(Self.exitCheckRetry)) с")
        }
    }

    private func describeOK(_ tunnel: TunnelStatus, _ server: ServerDetector.Candidate?, _ country: CountryInfo?) -> String {
        var text = tunnel.description
        if let server {
            text += ", сервер \(server.address)"
            if let code = country?.code, let country { text += " (\(countryName(code)), \(country.sourceDescription))" }
        }
        return text
    }

    // MARK: - Заморозка вне проверки

    /// Заморозить всё защищаемое независимо от состояния (перед сном Mac).
    public func freezeAll(reason: String) {
        let processes = ProcessList.all()
        let byPid = Dictionary(uniqueKeysWithValues: processes.map { ($0.pid, $0) })
        let protected = Matcher.find(apps: apps, in: processes).reduce(into: Set<pid_t>()) { $0.formUnion($1.pids) }
        let toFreeze = protected.subtracting(frozen.keys).filter { byPid[$0]?.isStopped == false }
        guard !toFreeze.isEmpty else { return }
        let outcome = dryRun ? Freezer.Outcome(done: Array(toFreeze)) : Freezer.freeze(toFreeze, processes: processes)
        let now = Date()
        for pid in outcome.done {
            frozen[pid] = State.Frozen(pid: pid, path: byPid[pid]?.path ?? "", since: now)
        }
        logger.log("\(reason) — заморожено \(plural(outcome.done.count, Words.processes))\(dryRun ? " (пробный режим)" : "")")
        report(outcome)
        persist(lastTunnel ?? TunnelStatus(interface: nil))
    }

    /// Отпустить всё, что держим. Вызывается при выходе: иначе программы останутся висеть.
    public func releaseAll(reason: String) {
        guard !frozen.isEmpty else { return }
        let processes = ProcessList.all()
        let pids = Set(frozen.keys)
        let outcome = dryRun ? Freezer.Outcome(done: Array(pids)) : Freezer.resume(pids, processes: processes)
        logger.log("\(reason) — отпускаю \(plural(outcome.done.count, Words.processes))")
        report(outcome)
        frozen = [:]
        persist(lastTunnel ?? sources.tunnel())
    }

    private func report(_ outcome: Freezer.Outcome) {
        for failure in outcome.failed {
            logger.log("  не удалось для pid \(failure.pid): \(failure.error)")
        }
    }

    private func persist(_ tunnel: TunnelStatus) {
        var state = State()
        state.frozen = frozen.values.sorted { $0.pid < $1.pid }
        state.lastTunnelInterface = tunnel.interface
        StateStore.save(state)
    }
}
