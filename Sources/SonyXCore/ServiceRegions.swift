import Foundation

/// Название страны по коду ISO: «Нидерланды (NL)». Словарь названий встроен в macOS,
/// своей таблицы не нужно. Код остаётся в скобках — он нужен в командах `sonyx allow country NL`.
/// Для неизвестного кода — сам код.
public func countryName(_ code: String) -> String {
    let code = code.uppercased()
    guard let name = Locale(identifier: "ru_RU").localizedString(forRegionCode: code), name != code else { return code }
    return "\(name) (\(code))"
}

/// Проверка 8 из CHECKS.md: в каких странах сервисы ИИ официально доступны.
/// Списки сверены 06.11.2026:
/// - Anthropic: https://www.anthropic.com/supported-countries
/// - OpenAI:    https://help.openai.com/en/articles/7947663-chatgpt-supported-countries
/// Cursor своего списка не публикует и отсылает к спискам провайдеров.
public enum ServiceRegions {
    public enum Service: String, CaseIterable {
        case claude = "Claude"
        case chatgpt = "ChatGPT"
        case cursor = "Cursor"
    }

    public enum Status: Equatable {
        case supported
        /// Страна в списке, но с оговорками (Украина без отдельных регионов).
        case supportedWithExceptions
        case unsupported
        case unknown
    }

    private static let anthropic: Set<String> = Set("""
    AL DZ AD AO AG AR AM AU AT AZ BS BH BD BB BE BZ BJ BT BO BA BW BR BN BG BF BI CV KH CM CA CF TD CL CO KM CG CD CR CI HR CY CZ
    DK DJ DM DO EC EG SV GQ ER EE SZ ET FJ FI FR GA GM GE DE GH GR GD GT GN GW GY HT HN HU IS IN ID IQ IE IL IT JM JP JO KZ KE KI
    KW KG LA LV LB LS LR LY LI LT LU MG MW MY MV ML MT MH MR MU MX FM MD MC MN ME MA MZ NA NR NP NL NZ NI NE NG MK NO OM PK PW PS
    PA PG PY PE PH PL PT QA RO RW KN LC VC WS SM ST SA SN RS SC SL SG SK SI SO SB ZA KR SS ES LK SD SR SE CH TW TJ TZ TH TL TG TO
    TT TN TR TM TV UG UA AE GB US UY UZ VU VA VN ZM ZW
    """.split(whereSeparator: { $0 == " " || $0 == "\n" }).map(String.init))

    /// Anthropic: «территории и зависимые владения перечисленных стран тоже поддерживаются».
    private static let anthropicTerritories: Set<String> = Set("""
    PR GU VI AS MP GI BM KY VG FK IM JE GG TC AI MS SH GF GP MQ RE YT PF NC PM BL MF WF TF AW CW SX BQ GL FO AX SJ CK NU TK
    """.split(whereSeparator: { $0 == " " || $0 == "\n" }).map(String.init))

    private static let openai: Set<String> = anthropic.union(Set("""
    AF AX AW BM KY FO GF PF TF GL GP MQ YT MM NC RE BL SH MF PM SJ WF YE
    """.split(whereSeparator: { $0 == " " || $0 == "\n" }).map(String.init)))

    private static let withExceptions: Set<String> = ["UA"]

    public static func status(of service: Service, country: String?) -> Status {
        guard let country = country?.uppercased(), country.count == 2 else { return .unknown }
        let list: Set<String>
        switch service {
        case .claude, .cursor:
            list = anthropic.union(anthropicTerritories)
        case .chatgpt:
            list = openai
        }
        guard list.contains(country) else { return .unsupported }
        return withExceptions.contains(country) ? .supportedWithExceptions : .supported
    }

    public static func describe(_ status: Status, service: Service) -> String {
        let suffix = service == .cursor ? " (по правилам Anthropic)" : ""
        switch status {
        case .supported: return "в списке\(suffix)"
        case .supportedWithExceptions: return "в списке, с исключениями по регионам\(suffix)"
        case .unsupported: return "НЕ в списке\(suffix)"
        case .unknown: return "страна неизвестна"
        }
    }
}
