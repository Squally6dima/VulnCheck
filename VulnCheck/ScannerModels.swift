import Foundation

enum Severity: String, Codable, CaseIterable {
    case critical
    case high
    case medium
    case low
    case info

    var title: String { rawValue.capitalized }
}

struct Finding: Identifiable, Codable {
    let id = UUID()
    let title: String
    let severity: Severity
    let detail: String
    let evidence: String
    let remediation: String
}

struct ScanReport: Codable {
    let target: URL
    let finalURL: URL?
    let statusCode: Int
    let findings: [Finding]
    let scannedAt: Date
}
