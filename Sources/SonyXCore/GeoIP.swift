import Foundation

/// Локальная база «адрес → страна» (DB-IP Lite, см. Resources/GEOIP-LICENSE.txt).
/// Формат файла описан в Tools/geoip-convert.swift. Ничего не отправляет наружу.
public final class GeoIP {
    private let data: Data
    private let count: Int
    private let startsOffset: Int
    private let countriesOffset: Int
    private let table: [String]

    public enum LoadError: Error { case missing, corrupted }

    public static let shared: GeoIP? = try? GeoIP()

    public convenience init() throws {
        guard let url = Bundle.module.url(forResource: "geoip-v4", withExtension: "bin") else {
            throw LoadError.missing
        }
        try self.init(contentsOf: url)
    }

    public init(contentsOf url: URL) throws {
        data = try Data(contentsOf: url, options: .mappedIfSafe)
        guard data.count > 8, data[0..<4] == Data("SXG1".utf8) else { throw LoadError.corrupted }
        count = Int(GeoIP.readUInt32(data, at: 4))
        startsOffset = 8
        countriesOffset = startsOffset + count * 4
        let tableCountOffset = countriesOffset + count
        guard data.count > tableCountOffset else { throw LoadError.corrupted }
        let tableCount = Int(data[tableCountOffset])
        guard data.count >= tableCountOffset + 1 + tableCount * 2 else { throw LoadError.corrupted }
        var codes: [String] = []
        for i in 0..<tableCount {
            let at = tableCountOffset + 1 + i * 2
            codes.append(String(decoding: data[at..<at + 2], as: UTF8.self))
        }
        table = codes
    }

    /// Код страны ISO 3166-1 alpha-2 или nil для частных, служебных и неизвестных адресов.
    public func country(of address: String) -> String? {
        guard let ip = GeoIP.parseIPv4(address) else { return nil }
        return country(of: ip)
    }

    public func country(of ip: UInt32) -> String? {
        guard count > 0 else { return nil }
        // Последний диапазон, начало которого ≤ ip.
        var low = 0
        var high = count - 1
        while low < high {
            let mid = (low + high + 1) / 2
            if start(mid) <= ip { low = mid } else { high = mid - 1 }
        }
        let code = table[Int(data[countriesOffset + low])]
        return code == "ZZ" ? nil : code
    }

    private func start(_ index: Int) -> UInt32 {
        GeoIP.readUInt32(data, at: startsOffset + index * 4)
    }

    private static func readUInt32(_ data: Data, at offset: Int) -> UInt32 {
        UInt32(data[offset]) << 24 | UInt32(data[offset + 1]) << 16 | UInt32(data[offset + 2]) << 8 | UInt32(data[offset + 3])
    }

    public static func parseIPv4(_ text: String) -> UInt32? {
        let parts = text.split(separator: ".")
        guard parts.count == 4 else { return nil }
        var value: UInt32 = 0
        for part in parts {
            guard let octet = UInt32(part), octet < 256 else { return nil }
            value = value << 8 | octet
        }
        return value
    }

    /// Частный или служебный адрес (домашняя сеть, localhost, фиктивные адреса туннеля 198.18.x).
    public static func isPrivate(_ address: String) -> Bool {
        guard let ip = parseIPv4(address) else { return true }
        let a = ip >> 24, b = (ip >> 16) & 0xff
        if a == 10 || a == 127 || a == 0 { return true }
        if a == 172, (16...31).contains(b) { return true }
        if a == 192, b == 168 { return true }
        if a == 169, b == 254 { return true }
        if a == 100, (64...127).contains(b) { return true }   // CGNAT
        if a == 198, (18...19).contains(b) { return true }    // benchmark / fake-IP у xray
        return false
    }
}
