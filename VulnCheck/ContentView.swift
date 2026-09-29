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
    @State private var selectedSection = 0

    var body: some View {
        NavigationStack {
            ZStack {
                Color(.systemBackground)
                    .ignoresSafeArea()

                GeometryReader { geometry in
                    ScrollView {
                        VStack(spacing: 16) {
                        header

                        Picker("Section", selection: $selectedSection) {
                            Text("Scanner").tag(0)
                            Text("Exploits").tag(1)
                            Text("Findings").tag(2)
                            Text("CoreTrust").tag(3)
                        }
                        .pickerStyle(.segmented)

                        switch selectedSection {
                        case 0:
                            scannerSection
                        case 1:
                            ExploitCatalogView()
                        case 3:
                            CoreTrustLabView()
                        default:
                            findingsSection
                        }
                    }
                    .frame(maxWidth: .infinity, minHeight: geometry.size.height, alignment: .top)
                        .padding(.top, 8)
                        .padding(.bottom, max(16, geometry.safeAreaInsets.bottom + 8))
                    }
                    .scrollIndicators(.hidden)
                }
                .ignoresSafeArea(edges: .bottom)
            }
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .principal) {
                    Text("VulnCheck")
                        .font(.headline.weight(.bold))
                }
            }
        }
    }

    private var header: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Image(systemName: "shield.lefthalf.filled")
                    .font(.system(size: 30, weight: .bold))
                    .foregroundStyle(.blue)

                VStack(alignment: .leading, spacing: 2) {
                    Text("Security Audit")
                        .font(.title2.weight(.bold))
                    Text("Passive checks for authorized targets")
                        .font(.subheadline)
                        .foregroundStyle(.secondary)
                }

                Spacer()
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(18)
        .background(.background, in: RoundedRectangle(cornerRadius: 22, style: .continuous))
        .overlay(
            RoundedRectangle(cornerRadius: 22, style: .continuous)
                .stroke(.quaternary, lineWidth: 1)
        )
    }

    private var scannerSection: some View {
        VStack(spacing: 14) {
            VStack(alignment: .leading, spacing: 12) {
                Label("Target", systemImage: "globe")
                    .font(.headline)

                TextField("https://example.com", text: $model.target)
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()
                    .keyboardType(.URL)
                    .padding(13)
                    .background(Color(.secondarySystemBackground), in: RoundedRectangle(cornerRadius: 13))

                Button {
                    model.scan()
                } label: {
                    HStack(spacing: 9) {
                        if model.isScanning {
                            ProgressView()
                                .tint(.white)
                        } else {
                            Image(systemName: "waveform.path.ecg")
                        }
                        Text(model.isScanning ? "Scanning…" : "Start security scan")
                            .fontWeight(.semibold)
                    }
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 14)
                }
                .buttonStyle(.borderedProminent)
                .disabled(model.isScanning)
            }
            .padding(18)
            .background(.background, in: RoundedRectangle(cornerRadius: 22, style: .continuous))

            if let error = model.errorMessage {
                statusCard(
                    title: "Scan failed",
                    detail: error,
                    icon: "exclamationmark.triangle.fill",
                    tint: .red
                )
            }

            if let report = model.report {
                summaryCards(report)
                scanMeta(report)
            }

            scopeCard
        }
    }

    private var findingsSection: some View {
        VStack(spacing: 12) {
            if let report = model.report {
                if report.findings.isEmpty {
                    statusCard(
                        title: "No findings",
                        detail: "The configured passive checks did not report a finding.",
                        icon: "checkmark.shield.fill",
                        tint: .green
                    )
                } else {
                    ForEach(report.findings) { finding in
                        FindingRow(finding: finding)
                    }
                }
            } else {
                statusCard(
                    title: "No scan yet",
                    detail: "Run a scan to populate security findings.",
                    icon: "shield",
                    tint: .secondary
                )
            }
        }
    }

    private func summaryCards(_ report: ScanReport) -> some View {
        let critical = report.findings.filter { $0.severity == .critical }.count
        let high = report.findings.filter { $0.severity == .high }.count
        let medium = report.findings.filter { $0.severity == .medium }.count
        let low = report.findings.filter { $0.severity == .low }.count

        return HStack(spacing: 10) {
            metricCard(title: "Critical", value: critical, tint: .red)
            metricCard(title: "High", value: high, tint: .orange)
            metricCard(title: "Medium", value: medium, tint: .yellow)
            metricCard(title: "Low", value: low, tint: .blue)
        }
    }

    private func metricCard(title: String, value: Int, tint: Color) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(title)
                .font(.caption)
                .foregroundStyle(.secondary)
            Text(String(value))
                .font(.title3.weight(.bold))
                .foregroundStyle(tint)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(13)
        .background(.background, in: RoundedRectangle(cornerRadius: 16, style: .continuous))
    }

    private func scanMeta(_ report: ScanReport) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            Label("Scan result", systemImage: "checkmark.circle")
                .font(.headline)

            LabeledContent("HTTP", value: String(report.statusCode))
            LabeledContent("Findings", value: String(report.findings.count))
            LabeledContent("Final URL", value: report.finalURL?.absoluteString ?? "—")
        }
        .padding(18)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(.background, in: RoundedRectangle(cornerRadius: 22, style: .continuous))
    }

    private var scopeCard: some View {
        HStack(alignment: .top, spacing: 10) {
            Image(systemName: "lock.shield")
                .foregroundStyle(.blue)

            Text("Authorized, passive HTTP response checks only. No exploit payloads, credential attacks, port scanning, brute force, or destructive requests.")
                .font(.footnote)
                .foregroundStyle(.secondary)
        }
        .padding(16)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(.background, in: RoundedRectangle(cornerRadius: 18, style: .continuous))
    }

    private func statusCard(title: String, detail: String, icon: String, tint: Color) -> some View {
        HStack(alignment: .top, spacing: 12) {
            Image(systemName: icon)
                .font(.title3)
                .foregroundStyle(tint)

            VStack(alignment: .leading, spacing: 4) {
                Text(title)
                    .font(.headline)
                Text(detail)
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
            }

            Spacer()
        }
        .padding(18)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(.background, in: RoundedRectangle(cornerRadius: 22, style: .continuous))
    }
}

struct FindingRow: View {
    let finding: Finding
    @State private var expanded = false

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Button {
                withAnimation(.easeInOut(duration: 0.2)) {
                    expanded.toggle()
                }
            } label: {
                HStack(spacing: 12) {
                    Image(systemName: severityIcon)
                        .font(.title3.weight(.semibold))
                        .foregroundStyle(severityColor)
                        .frame(width: 30)

                    VStack(alignment: .leading, spacing: 3) {
                        Text(finding.title)
                            .font(.headline)
                            .foregroundStyle(.primary)
                            .multilineTextAlignment(.leading)

                        Text(finding.severity.title)
                            .font(.caption.weight(.semibold))
                            .foregroundStyle(severityColor)
                    }

                    Spacer()

                    Image(systemName: expanded ? "chevron.up" : "chevron.down")
                        .font(.caption.weight(.bold))
                        .foregroundStyle(.secondary)
                }
            }
            .buttonStyle(.plain)

            if expanded {
                VStack(alignment: .leading, spacing: 9) {
                    Text(finding.detail)
                        .font(.subheadline)

                    detailLine("Evidence", finding.evidence)
                    detailLine("Fix", finding.remediation)
                }
                .padding(.leading, 42)
            }
        }
        .padding(16)
        .background(.background, in: RoundedRectangle(cornerRadius: 20, style: .continuous))
    }

    private func detailLine(_ title: String, _ value: String) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(title)
                .font(.caption.weight(.semibold))
                .foregroundStyle(.secondary)
            Text(value)
                .font(.caption)
        }
    }

    private var severityColor: Color {
        switch finding.severity {
        case .critical, .high: return .red
        case .medium: return .orange
        case .low: return .yellow
        case .info: return .secondary
        }
    }

    private var severityIcon: String {
        switch finding.severity {
        case .critical: return "xmark.octagon.fill"
        case .high: return "exclamationmark.octagon.fill"
        case .medium: return "exclamationmark.triangle.fill"
        case .low: return "info.circle.fill"
        case .info: return "checkmark.circle.fill"
        }
    }
}
