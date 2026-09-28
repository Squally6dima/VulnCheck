import SwiftUI

@MainActor
final class ScanViewModel: ObservableObject {
    @Published var target = "https://example.com"
    @Published private(set) var report: ScanReport?
    @Published private(set) var isScanning = false
    @Published var errorMessage: String?

    private let scanner = ScannerEngine()

    func scan() {
        guard !isScanning else { return }

        isScanning = true
        errorMessage = nil
        report = nil

        Task {
            do {
                report = try await scanner.scan(target: target)
            } catch {
                errorMessage = error.localizedDescription
            }
            isScanning = false
        }
    }
}

struct ContentView: View {
    @StateObject private var model = ScanViewModel()

    var body: some View {
        NavigationStack {
            Form {
                Section("Target") {
                    TextField("https://example.com", text: $model.target)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()

                    Button {
                        model.scan()
                    } label: {
                        HStack {
                            if model.isScanning {
                                ProgressView()
                            }
                            Text(model.isScanning ? "Scanning…" : "Start scan")
                        }
                    }
                    .disabled(model.isScanning)
                }

                if let error = model.errorMessage {
                    Section("Error") {
                        Text(error).foregroundStyle(.red)
                    }
                }

                if let report = model.report {
                    Section("Result") {
                        LabeledContent("HTTP status", value: String(report.statusCode))
                        LabeledContent("Final URL", value: report.finalURL?.absoluteString ?? "—")
                        LabeledContent("Findings", value: String(report.findings.count))
                    }

                    Section("Findings") {
                        if report.findings.isEmpty {
                            Label("No configured checks reported a finding.", systemImage: "checkmark.shield")
                                .foregroundStyle(.green)
                        } else {
                            ForEach(report.findings) { finding in
                                FindingRow(finding: finding)
                            }
                        }
                    }
                }

                Section("Scope") {
                    Text("Passive HTTP response checks only. No exploit payloads, credential attacks, port scanning, or destructive requests.")
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                }
            }
            .navigationTitle("VulnCheck")
        }
    }
}

struct FindingRow: View {
    let finding: Finding
    @State private var expanded = false

    var body: some View {
        Button {
            expanded.toggle()
        } label: {
            VStack(alignment: .leading, spacing: 6) {
                HStack {
                    Text(finding.title).font(.headline)
                    Spacer()
                    Text(finding.severity.title)
                        .font(.caption.weight(.semibold))
                        .foregroundStyle(severityColor)
                }

                if expanded {
                    Text(finding.detail).font(.subheadline)
                    Text("Evidence: (finding.evidence)")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                    Text("Fix: (finding.remediation)")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }
        }
        .buttonStyle(.plain)
    }

    private var severityColor: Color {
        switch finding.severity {
        case .critical, .high: return .red
        case .medium: return .orange
        case .low: return .yellow
        case .info: return .secondary
        }
    }
}
