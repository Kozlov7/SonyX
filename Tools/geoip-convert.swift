#!/usr/bin/env swift
// Конвертер базы DB-IP Lite Country (CSV) в компактный двоичный файл для SonyX.
//
// Использование:
//   curl -sL -o /tmp/dbip.csv.gz https://download.db-ip.com/free/dbip-country-lite-YYYY-MM.csv.gz
//   gunzip /tmp/dbip.csv.gz
//   swift Tools/geoip-convert.swift /tmp/dbip.csv Sources/SonyXCore/Resources/geoip-v4.bin
//
// Формат файла (все числа big-endian):
//   "SXG1"                 — подпись
//   UInt32 count           — число диапазонов
//   UInt32[count] starts   — начало каждого диапазона, по возрастанию; конец = следующее начало − 1
//   UInt8[count]  country  — индекс страны в таблице
//   UInt8  tableCount
//   [2 байта ASCII] × tableCount — коды стран ISO 3166-1 alpha-2; "ZZ" = неизвестно
//
// Берутся только IPv4-диапазоны. Соседние диапазоны одной страны склеиваются,
// пропуски заполняются "ZZ", поэтому любой адрес попадает ровно в один диапазон.

import Foundation

let args = CommandLine.arguments
guard args.count == 3 else {
    FileHandle.standardError.write(Data("Использование: geoip-convert.swift <dbip.csv> <geoip-v4.bin>\n".utf8))
    exit(2)
}

func ipv4(_ text: Substring) -> UInt32? {
    let parts = text.split(separator: ".")
    guard parts.count == 4 else { return nil }
    var value: UInt32 = 0
    for part in parts {
        guard let octet = UInt32(part), octet < 256 else { return nil }
        value = value << 8 | octet
    }
    return value
}

guard let csv = try? String(contentsOfFile: args[1], encoding: .utf8) else {
    FileHandle.standardError.write(Data("Не удалось прочитать \(args[1])\n".utf8))
    exit(1)
}

struct Range { var start: UInt32; var end: UInt32; var country: String }
var ranges: [Range] = []
for line in csv.split(separator: "\n") {
    let fields = line.split(separator: ",")
    guard fields.count == 3, let start = ipv4(fields[0]), let end = ipv4(fields[1]) else { continue }
    var country = String(fields[2]).trimmingCharacters(in: .whitespacesAndNewlines).uppercased()
    if country.count != 2 { country = "ZZ" }
    ranges.append(Range(start: start, end: end, country: country))
}
ranges.sort { $0.start < $1.start }

// Заполнить пропуски и склеить соседей.
var merged: [Range] = []
var cursor: UInt64 = 0
for range in ranges {
    if UInt64(range.start) > cursor {
        merged.append(Range(start: UInt32(cursor), end: range.start - 1, country: "ZZ"))
    }
    if let last = merged.last, last.country == range.country, UInt64(last.end) + 1 == UInt64(range.start) {
        merged[merged.count - 1].end = range.end
    } else {
        merged.append(range)
    }
    cursor = UInt64(range.end) + 1
}
if cursor <= UInt64(UInt32.max) {
    merged.append(Range(start: UInt32(cursor), end: UInt32.max, country: "ZZ"))
}

var table: [String] = []
var index: [String: UInt8] = [:]
for range in merged where index[range.country] == nil {
    guard table.count < 255 else { fatalError("слишком много стран") }
    index[range.country] = UInt8(table.count)
    table.append(range.country)
}

var out = Data()
out.append(contentsOf: Array("SXG1".utf8))
func appendUInt32(_ value: UInt32) {
    var be = value.bigEndian
    withUnsafeBytes(of: &be) { out.append(contentsOf: $0) }
}
appendUInt32(UInt32(merged.count))
for range in merged { appendUInt32(range.start) }
for range in merged { out.append(index[range.country]!) }
out.append(UInt8(table.count))
for code in table { out.append(contentsOf: Array(code.utf8)) }

do {
    try out.write(to: URL(fileURLWithPath: args[2]))
} catch {
    FileHandle.standardError.write(Data("Не удалось записать \(args[2]): \(error)\n".utf8))
    exit(1)
}
print("Диапазонов в CSV: \(ranges.count), после склейки: \(merged.count), стран: \(table.count), размер: \(out.count / 1024) КБ")
