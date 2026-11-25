import Darwin
import Foundation
import SonyXCore

let usage = """
sonyx — сторож для программ, которым нельзя в интернет мимо VPN (прототип, этап 3)

Команды:
  status                 туннель, сервер, страна, DNS, IPv6, защищаемые процессы
  mode light|medium|strict
                         лёгкий — пауза только в запрещённых странах (встроенный список + deny)
                         средний — пауза везде, кроме разрешённых стран (allow country)
                         жёсткий — пауза везде, кроме разрешённых адресов сервера (allow ip)
                         во всех режимах: туннель упал или IPv6 наружу — пауза
  allow country <XX>     разрешить страну (код ISO: DE, NL…) — для среднего режима
  allow ip <адрес>       разрешить адрес сервера — для жёсткого режима
  allow current          разрешить текущий сервер и его страну
  disallow country|ip …  убрать из разрешённых
  deny country <XX>      запретить страну — для лёгкого режима
  undeny country <XX>    убрать из запрещённых
  exit-check             что видит сайт: запрос к claude.ai/cdn-cgi/trace (только при туннеле)
  autocheck on|off       сторож сам проверяет выход при новом сервере и переподключении (вкл)
  recheck <минуты>       плановая перепроверка выхода раз в N минут (30; 0 — выключить)
  watch [--interval N] [--dry-run]
                         следить и замораживать при падении туннеля (Ctrl-C отпускает всё)
  release [--all]        отпустить замороженное SonyX (после сбоя); --all — все остановленные
                         процессы защищаемых программ, включая остановленные вами (Ctrl-Z)
  selftest               проверить заморозку на безвредном процессе `sleep`
  log [N]                последние N строк журнала (по умолчанию 30)
  geo <ip>               страна адреса по локальной базе (для отладки)

Файлы: \(StateStore.directory.path)
"""

func print(_ text: String) {
    FileHandle.standardOutput.write(Data((text + "\n").utf8))
}

/// Настройки для команд, которые будут их сохранять. При повреждённом файле — объяснение и nil.
func loadConfigForWriting() -> Config? {
    let loaded = Config.load()
    if let error = loaded.error {
        print("Файл настроек повреждён, ничего не меняю: \(error)")
        print("Исправьте файл или переместите его в Корзину — тогда SonyX создаст новый при следующем запуске.")
        return nil
    }
    return loaded.config
}

func status() {
    let tunnel = TunnelCheck.check()
    let ipv6 = Diagnostics.ipv6()
    let dns = Diagnostics.dns()
    let loaded = Config.load()
    let config = loaded.config
    if let error = loaded.error {
        print("ОШИБКА НАСТРОЕК: \(error)")
        print("            SonyX работает с пустыми настройками и ничего не сохраняет. Страна сервера не проверяется.")
        print("")
    }
    let processes = ProcessList.all()
    let geo = GeoIP.shared

    var server: ServerDetector.Candidate?
    if tunnel.isUp {
        let detector = ServerDetector()
        server = detector.update(with: Connections.established())
    }
    let verdict = Policy.evaluate(tunnel: tunnel, ipv6Leak: ipv6.isLeak, server: server, config: config, geo: geo)

    switch verdict {
    case .ok: print("Состояние:  всё в порядке")
    case .pause(let reason, let hint):
        print("Состояние:  ПАУЗА — \(reason)")
        if let hint { print("            что делать: \(hint)") }
    case .learn: print("Состояние:  защита ещё не включалась — первый `sonyx watch` запомнит сервер и страну")
    }
    print("Режим:      \(config.mode.title) — \(config.mode.summary)")
    print("Автопроверка выхода: \(config.autoCheck ? "вкл — при новом сервере и переподключении" + (config.recheckMinutes > 0 ? ", плюс раз в \(config.recheckMinutes) мин" : "") : "выкл — только вручную (sonyx exit-check)")")
    print("Туннель:    \(tunnel.description)")
    if let server {
        let byDatabase = geo?.country(of: server.address)
        print("Сервер VPN: \(server.address)\(byDatabase.map { " · \(countryName($0)) по базе" } ?? " · страна неизвестна") · \(plural(server.connections, Words.connections)) (\(server.command))")
        let info = CountryInfo.resolve(server: server.address, config: config, geo: geo)
        if let exit = config.exits[server.address] {
            let when = DateFormatter.localizedString(from: exit.checkedAt, dateStyle: .short, timeStyle: .short)
            print("Выход:      \(exit.ip)\(exit.country.map { " · \(countryName($0))" } ?? "") — по проверке \(when); решение принимается по этой стране")
            if let a = exit.country, let b = byDatabase, a != b {
                print("            страна выхода — \(countryName(a)), а сервер по базе — \(countryName(b)) — цепочка серверов или неточность базы")
            }
        } else {
            print("Выход:      не проверялся — решение принимается по базе; `sonyx exit-check` покажет, что видит сайт на самом деле")
        }
        for service in ServiceRegions.Service.allCases {
            let status = ServiceRegions.status(of: service, country: info.code)
            print("            \(service.rawValue.padding(toLength: 8, withPad: " ", startingAt: 0)) \(ServiceRegions.describe(status, service: service))")
        }
    } else if tunnel.isUp {
        print("Сервер VPN: пока не виден (нет соединений с сервером)")
    }
    print("IPv6:       \(ipv6.description)")
    print("DNS:        \(dns.description)")
    print("Часовой пояс: \(Diagnostics.timezone())")
    print("Разрешено:  страны \(config.allowed.countries.isEmpty ? "—" : config.allowed.countries.map(countryName).joined(separator: ", "))"
          + "; адреса \(config.allowed.ips.isEmpty ? "—" : config.allowed.ips.joined(separator: ", "))")
    print("Запрещено:  \(config.denied.countries.isEmpty ? "только встроенный список стран, где Claude не работает" : config.denied.countries.map(countryName).joined(separator: ", ") + " и встроенный список")")
    print("")
    print("Под защитой:")
    for item in Matcher.find(apps: ProtectedApp.defaults, in: processes) {
        let state: String
        if item.pids.isEmpty {
            state = "не запущен"
        } else if item.frozenCount == item.pids.count {
            state = "ЗАМОРОЖЕН (\(plural(item.pids.count, Words.processes)))"
        } else if item.frozenCount > 0 {
            state = "частично заморожен (\(item.frozenCount) из \(item.pids.count))"
        } else {
            state = "работает (\(plural(item.pids.count, Words.processes)))"
        }
        print("  \(item.app.name.padding(toLength: 16, withPad: " ", startingAt: 0)) \(state)")
    }
    let saved = StateStore.load()
    let stale = StateStore.stillFrozen(saved, in: processes)
    if !stale.isEmpty {
        print("")
        print("Внимание: с прошлого запуска всё ещё заморожено: \(plural(stale.count, Words.processes)). `sonyx release` отпустит.")
    }
}

func allow(_ args: [String]) -> Int32 {
    guard var config = loadConfigForWriting() else { return 1 }
    switch (args.first, args.dropFirst().first) {
    case ("country", let code?):
        guard code.count == 2 else { print("Код страны — две буквы, например DE"); return 2 }
        config.allow(country: code)
        config.save()
        print("Разрешена страна \(countryName(code)). Теперь: \(config.allowed.countries.map(countryName).joined(separator: ", "))")
    case ("ip", let ip?):
        guard GeoIP.parseIPv4(ip) != nil else { print("Это не IPv4-адрес: \(ip)"); return 2 }
        config.allow(ip: ip)
        config.save()
        print("Разрешён адрес \(ip). Теперь: \(config.allowed.ips.joined(separator: ", "))")
    case ("current", _):
        guard TunnelCheck.check().isUp else { print("Туннель не поднят — текущего сервера нет."); return 1 }
        guard let server = ServerDetector().update(with: Connections.established()) else {
            print("Сервер пока не виден: нет соединений. Откройте что-нибудь в браузере и повторите."); return 1
        }
        let info = CountryInfo.resolve(server: server.address, config: config, geo: GeoIP.shared)
        config.allow(ip: server.address)
        if let country = info.code { config.allow(country: country) }
        config.save()
        print("Разрешён сервер \(server.address)\(info.code.map { " и страна \(countryName($0)) (\(info.sourceDescription))" } ?? "").")
        if info.isExitUnknown {
            print("Выход через этот сервер не проверялся: страна взята по базе и может отличаться от настоящей. Проверить: sonyx exit-check")
        }
    default:
        print("Использование: sonyx allow country <XX> | ip <адрес> | current")
        return 2
    }
    if config.mode == .light {
        print("Сейчас лёгкий режим: разрешённые списки в нём не используются (пригодятся в среднем и жёстком).")
    }
    return 0
}

func disallow(_ args: [String]) -> Int32 {
    guard var config = loadConfigForWriting() else { return 1 }
    switch (args.first, args.dropFirst().first) {
    case ("country", let code?):
        guard config.disallow(country: code) else { print("Страны \(countryName(code)) в разрешённых не было."); return 1 }
        config.save()
        print("Страна \(countryName(code)) убрана. Теперь: \(config.allowed.countries.isEmpty ? "—" : config.allowed.countries.map(countryName).joined(separator: ", "))")
    case ("ip", let ip?):
        guard config.disallow(ip: ip) else { print("Адреса \(ip) в разрешённых не было."); return 1 }
        config.save()
        print("Адрес \(ip) убран. Теперь: \(config.allowed.ips.isEmpty ? "—" : config.allowed.ips.joined(separator: ", "))")
    default:
        print("Использование: sonyx disallow country <XX> | ip <адрес>")
        return 2
    }
    return 0
}

func deny(_ args: [String], undo: Bool) -> Int32 {
    guard args.first == "country", let code = args.dropFirst().first, code.count == 2 else {
        print("Использование: sonyx \(undo ? "undeny" : "deny") country <XX>"); return 2
    }
    guard var config = loadConfigForWriting() else { return 1 }
    if undo {
        guard config.undeny(country: code) else { print("Страны \(countryName(code)) в запрещённых не было."); return 1 }
        print("Страна \(countryName(code)) убрана из запрещённых.")
    } else {
        config.deny(country: code)
        print("Страна \(countryName(code)) запрещена.")
    }
    config.save()
    print("Запрещено: \(config.denied.countries.isEmpty ? "только встроенный список" : config.denied.countries.map(countryName).joined(separator: ", ") + " и встроенный список")")
    if config.mode != .light {
        print("Сейчас \(config.mode.title) режим: чёрный список работает только в лёгком.")
    }
    return 0
}

func setAutoCheck(_ value: String?) -> Int32 {
    guard let value, ["on", "off"].contains(value) else { print("Использование: sonyx autocheck on | off"); return 2 }
    guard var config = loadConfigForWriting() else { return 1 }
    config.autoCheck = value == "on"
    config.save()
    if config.autoCheck {
        print("Автопроверка выхода включена: при новом сервере, переподключении\(config.recheckMinutes > 0 ? " и раз в \(config.recheckMinutes) мин" : "").")
    } else {
        print("Автопроверка выхода выключена. Страна определяется по базе, пока вы не запустите sonyx exit-check вручную — с автовыбором сервера в VPN-клиенте будут ложные паузы.")
    }
    return 0
}

func setRecheck(_ value: String?) -> Int32 {
    guard let value, let minutes = Int(value), minutes >= 0 else { print("Использование: sonyx recheck <минуты>  (0 — выключить)"); return 2 }
    guard var config = loadConfigForWriting() else { return 1 }
    config.recheckMinutes = minutes
    config.save()
    print(minutes == 0 ? "Плановая перепроверка выключена; проверка только при новом сервере и переподключении."
                       : "Плановая перепроверка выхода: раз в \(plural(minutes, ("минуту", "минуты", "минут"))).")
    if !config.autoCheck { print("Автопроверка сейчас выключена (sonyx autocheck on), настройка вступит в силу после включения.") }
    return 0
}

func setMode(_ value: String?) -> Int32 {
    guard let value, let mode = Config.Mode(name: value) else {
        print("Использование: sonyx mode light | medium | strict"); return 2
    }
    guard var config = loadConfigForWriting() else { return 1 }
    config.mode = mode
    config.save()
    print("Режим: \(mode.title) — \(mode.summary).")
    switch mode {
    case .light:
        break
    case .medium where config.allowed.countries.isEmpty:
        print("Разрешённых стран пока нет — при поднятом туннеле всё будет на паузе. Добавьте: sonyx allow country <XX> или sonyx allow current")
    case .strict where config.allowed.ips.isEmpty:
        print("Разрешённых адресов пока нет — при поднятом туннеле всё будет на паузе. Добавьте: sonyx allow ip <адрес> или sonyx allow current")
    case .strict:
        print("Жёсткий режим имеет смысл, когда в VPN-клиенте выбран один сервер, а не автовыбор: иначе пауза при каждом переключении.")
    default:
        break
    }
    return 0
}

func exitCheck() -> Int32 {
    guard var config = loadConfigForWriting() else { return 1 }
    let tunnel = TunnelCheck.check()
    print("Запрос к https://\(config.traceHost)/cdn-cgi/trace без cookie…")
    switch ExitCheck.run(host: config.traceHost, tunnel: tunnel) {
    case .failure(let error):
        print("Не удалось: \(error)")
        return 1
    case .success(let result):
        print("Сайт видит: \(result.ip)\(result.country.map { " · \(countryName($0))" } ?? "")")
        if let server = ServerDetector().update(with: Connections.established()) {
            let serverCountry = GeoIP.shared?.country(of: server.address)
            config.exits[server.address] = Config.Exit(ip: result.ip, country: result.country, checkedAt: Date())
            config.save()
            print("Сервер VPN: \(server.address)\(serverCountry.map { " · \(countryName($0)) по базе" } ?? "") — запомнил, что через него выход \(result.ip)")
            if let a = result.country, let b = serverCountry, a != b {
                print("Страна выхода — \(countryName(a)), а сервер по базе — \(countryName(b)): либо цепочка серверов, либо неточность базы. Решение теперь принимается по стране выхода.")
            }
            if case .pause(let reason, let hint) = Policy.evaluate(tunnel: tunnel, ipv6Leak: false, server: server, config: config, geo: GeoIP.shared) {
                print("С учётом проверки защищаемые программы будут на паузе: \(reason)")
                if let hint { print("  что делать: \(hint)") }
            }
        }
        for service in ServiceRegions.Service.allCases {
            let status = ServiceRegions.status(of: service, country: result.country)
            print("  \(service.rawValue.padding(toLength: 8, withPad: " ", startingAt: 0)) \(ServiceRegions.describe(status, service: service))")
        }
        return 0
    }
}

func watch(interval: TimeInterval, dryRun: Bool) {
    let logger = Logger()
    let guardian = Guardian(dryRun: dryRun, logger: logger)
    let processes = ProcessList.all()
    guardian.warnIfLaunchedFromProtectedApp(processes: processes)
    guardian.restore(from: StateStore.load(), processes: processes)

    // Опрос — страховка. Пока всё спокойно, раз в `interval`; когда туннель лежит
    // или что-то заморожено — раз в секунду, чтобы ловить новые процессы.
    let fastInterval: TimeInterval = 1
    let timer = DispatchSource.makeTimerSource(queue: .main)
    var currentInterval: TimeInterval = 0
    func reschedule() {
        let wanted = guardian.wantsFastPolling ? min(fastInterval, interval) : interval
        guard wanted != currentInterval else { return }
        currentInterval = wanted
        timer.schedule(deadline: .now() + wanted, repeating: wanted)
    }
    func tick(trigger: String) {
        guardian.tick(trigger: trigger)
        reschedule()
    }
    timer.setEventHandler { tick(trigger: "опрос") }
    timer.schedule(deadline: .now(), repeating: interval)
    currentInterval = interval
    timer.resume()

    // События сети: несколько уведомлений подряд схлопываем в одну проверку.
    var pending: DispatchWorkItem?
    let network = NetworkWatcher { _ in
        pending?.cancel()
        let work = DispatchWorkItem { tick(trigger: "событие сети") }
        pending = work
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.1, execute: work)
    }
    let networkOK = network.start()

    let power = PowerWatcher { event in
        switch event {
        case .willSleep:
            guardian.willSleep()
            reschedule()
        case .didWake:
            guardian.didWake()
            reschedule()
        }
    }
    let powerOK = power.start()

    var how = ["опрос каждые \(Int(interval)) с"]
    how.append(networkOK ? "события сети" : "события сети НЕДОСТУПНЫ")
    how.append(powerOK ? "сон/пробуждение" : "сон/пробуждение НЕДОСТУПНЫ")
    logger.log("SonyX запущен\(dryRun ? " в пробном режиме (ничего не замораживает)" : ""): \(how.joined(separator: ", "))")

    // Ctrl-C, kill и закрытие окна терминала (SIGHUP) должны отпустить всё,
    // иначе программы останутся висеть.
    signal(SIGINT, SIG_IGN)
    signal(SIGTERM, SIG_IGN)
    signal(SIGHUP, SIG_IGN)
    let sources = [SIGINT, SIGTERM, SIGHUP].map { sig -> DispatchSourceSignal in
        let source = DispatchSource.makeSignalSource(signal: sig, queue: .main)
        source.setEventHandler {
            guardian.releaseAll(reason: "SonyX останавливается")
            logger.log("SonyX остановлен")
            exit(0)
        }
        source.resume()
        return source
    }
    _ = sources
    _ = network
    _ = power

    dispatchMain()
}

/// Отпустить то, что заморозил SonyX (по `state.json`). С `--all` — все остановленные
/// процессы защищаемых программ, включая остановленные самим пользователем (Ctrl-Z).
func release(all: Bool) {
    let processes = ProcessList.all()
    let state = StateStore.load()
    let ours = StateStore.stillFrozen(state, in: processes)
    let allStopped = Matcher.find(apps: ProtectedApp.defaults, in: processes)
        .reduce(into: Set<pid_t>()) { $0.formUnion($1.pids) }
        .filter { pid in processes.first { $0.pid == pid }?.isStopped == true }
    let targets = all ? allStopped : ours

    guard !targets.isEmpty else {
        if all || allStopped.isEmpty {
            print("Остановленных процессов нет.")
        } else {
            print("SonyX ничего не замораживал, но остановлено: \(plural(allStopped.count, Words.processes)) защищаемых программ (возможно, Ctrl-Z).")
            print("Отпустить и их: sonyx release --all")
        }
        return
    }
    let outcome = Freezer.resume(targets, processes: processes)
    print("Отпущено: \(plural(outcome.done.count, Words.processes)).")
    for failure in outcome.failed {
        print("  pid \(failure.pid): \(failure.error)")
    }
    let others = allStopped.subtracting(targets)
    if !all, !others.isEmpty {
        print("Ещё остановлено не SonyX: \(plural(others.count, Words.processes)). Отпустить и их: sonyx release --all")
    }
    var updated = state
    updated.frozen = []
    StateStore.save(updated)
}

func selftest() -> Int32 {
    print("Запускаю `sleep 300` и пробую заморозить его…")
    let child = Process()
    child.executableURL = URL(fileURLWithPath: "/bin/sleep")
    child.arguments = ["300"]
    do { try child.run() } catch {
        print("Не удалось запустить sleep: \(error)")
        return 1
    }
    let pid = child.processIdentifier
    defer { kill(pid, SIGKILL) }

    func isStopped() -> Bool {
        ProcessList.all().first { $0.pid == pid }?.isStopped == true
    }

    let freeze = Freezer.freeze([pid], processes: ProcessList.all())
    usleep(100_000)
    guard freeze.failed.isEmpty, isStopped() else {
        print("ОШИБКА: процесс \(pid) не остановился. \(freeze.failed)")
        return 1
    }
    print("  pid \(pid) заморожен — состояние SSTOP подтверждено")

    let resume = Freezer.resume([pid], processes: ProcessList.all())
    usleep(100_000)
    guard resume.failed.isEmpty, !isStopped() else {
        print("ОШИБКА: процесс \(pid) не возобновился. \(resume.failed)")
        return 1
    }
    print("  pid \(pid) отпущен — снова работает")
    print("Заморозка работает.")
    return 0
}

func showLog(lines: Int) {
    guard let data = try? Data(contentsOf: StateStore.logFile) else {
        print("Журнал пуст: \(StateStore.logFile.path)")
        return
    }
    let all = String(decoding: data, as: UTF8.self).split(separator: "\n")
    print(all.suffix(lines).joined(separator: "\n"))
}

var args = Array(CommandLine.arguments.dropFirst())
let command = args.isEmpty ? "help" : args.removeFirst()

switch command {
case "status":
    status()
case "watch":
    var interval: TimeInterval = 5
    var dryRun = false
    while !args.isEmpty {
        let arg = args.removeFirst()
        switch arg {
        case "--interval":
            interval = args.isEmpty ? 5 : (TimeInterval(args.removeFirst()) ?? 5)
        case "--dry-run":
            dryRun = true
        default:
            print("Неизвестный параметр: \(arg)")
            exit(2)
        }
    }
    watch(interval: max(1, interval), dryRun: dryRun)
case "allow":
    exit(allow(args))
case "disallow":
    exit(disallow(args))
case "deny":
    exit(deny(args, undo: false))
case "undeny":
    exit(deny(args, undo: true))
case "mode":
    exit(setMode(args.first))
case "exit-check":
    exit(exitCheck())
case "autocheck":
    exit(setAutoCheck(args.first))
case "recheck":
    exit(setRecheck(args.first))
case "release":
    release(all: args.first == "--all")
case "selftest":
    exit(selftest())
case "log":
    showLog(lines: Int(args.first ?? "") ?? 30)
case "geo":
    guard let geo = GeoIP.shared else { print("База GeoIP не загрузилась"); exit(1) }
    for ip in args {
        print("\(ip)  →  \(GeoIP.isPrivate(ip) ? "частный адрес" : (geo.country(of: ip).map(countryName) ?? "неизвестно"))")
    }
case "help", "-h", "--help":
    print(usage)
default:
    print("Неизвестная команда: \(command)\n")
    print(usage)
    exit(2)
}
