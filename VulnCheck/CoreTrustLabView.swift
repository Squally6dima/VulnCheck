import SwiftUI

@MainActor
final class CoreTrustLabViewModel: ObservableObject {
    @Published private(set) var report: MachOSignatureReport?
    @Published private(set) var evaluation: CoreTrustEvaluation?
    @Published private(set) var isRunning = false
    @Published var errorMessage: String?

    func runBaseline() {
        guard !isRunning else { return }

        isRunning = true
        errorMessage = nil
        report = nil
        evaluation = nil

        do {
            guard let executableURL = Bundle.main.executableURL else {
                throw MachOSignatureParser.ParserError.invalidMachO("Bundle executable URL is unavailable.")
            }

            let parsed = try MachOSignatureParser.analyze(url: executableURL)
            report = parsed

            guard let codeDirectory = parsed.codeDirectoryBlobs.first else {
                throw MachOSignatureParser.ParserError.invalidSignature("No CodeDirectory was available for CoreTrust evaluation.")
            }

            evaluation = CoreTrustRuntime.evaluate(
                cms: parsed.cms,
                codeDirectory: codeDirectory
            )
        } catch {
            errorMessage = error.localizedDescription
        }

        isRunning = false
    }
}

struct CoreTrustLabView: View {
    @StateObject private var model = CoreTrustLabViewModel()

    var body: some View {
        VStack(spacing: 14) {
            header

            Button {
                model.runBaseline()
            } label: {
                HStack(spacing: 8) {
                    if model.isRunning {
                        ProgressView()
                    } else {
                        Image(systemName: "testtube.2")
                    }

                    Text(model.isRunning ? "Running baseline…" : "Run CoreTrust baseline")
                        .fontWeight(.semibold)
                }
                .frame(maxWidth: .infinity)
                .padding(.vertical, 14)
            }
            .buttonStyle(.borderedProminent)
            .disabled(model.isRunning)

            if let error = model.errorMessage {
                infoCard(
                    title: "Baseline error",
                    detail: error,
                    icon: "exclamationmark.triangle.fill",
                    tint: .red
                )
            }

            if let report = model.report {
                signatureCard(report)
                codeDirectoryCard(report)
                signalsCard(report)
            }

            if let evaluation = model.evaluation {
                evaluationCard(evaluation)
            }

            researchScope
        }
    }

    private var header: some View {
        VStack(alignment: .leading, spacing: 7) {
            Label("CoreTrust Lab", systemImage: "checkmark.shield")
                .font(.title3.weight(.bold))

            Text("Local code-signature research surface for controlled, reproducible testing.")
                .font(.subheadline)
                .foregroundStyle(.secondary)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(18)
        .background(.background, in: RoundedRectangle(cornerRadius: 20, style: .continuous))
    }

    private func signatureCard(_ report: MachOSignatureReport) -> some View {
        VStack(alignment: .leading, spacing: 9) {
            Label("Embedded signature", systemImage: "doc.badge.gearshape")
                .font(.headline)

            LabeledContent("Offset", value: String(report.signatureOffset))
            LabeledContent("Size", value: String(report.signatureSize))
            LabeledContent("CMS", value: report.hasCMS ? "present" : "missing")
            LabeledContent("CodeDirectories", value: String(report.codeDirectories.count))
        }
        .padding(16)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(.background, in: RoundedRectangle(cornerRadius: 18, style: .continuous))
    }

    private func codeDirectoryCard(_ report: MachOSignatureReport) -> some View {
        VStack(alignment: .leading, spacing: 10) {
            Label("CodeDirectory", systemImage: "number")
                .font(.headline)

            ForEach(report.codeDirectories) { cd in
                VStack(alignment: .leading, spacing: 5) {
                    HStack {
                        Text("#(cd.index)")
                            .font(.caption.weight(.bold))
                        Spacer()
                        Text(cd.hashTypeName)
                            .font(.caption.weight(.semibold))
                            .foregroundStyle(.blue)
                    }

                    LabeledContent("Version", value: cd.versionName)
                    LabeledContent("Flags", value: String(format: "0x%08X", cd.flags))
                    LabeledContent("Special slots", value: String(cd.specialSlots))
                    LabeledContent("Code slots", value: String(cd.codeSlots))
                    LabeledContent("Code limit", value: String(cd.codeLimit))
                    LabeledContent("Page size", value: String(1 << cd.pageSize))
                }
                .padding(12)
                .background(Color(.secondarySystemBackground), in: RoundedRectangle(cornerRadius: 14, style: .continuous))
            }
        }
        .padding(16)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(.background, in: RoundedRectangle(cornerRadius: 18, style: .continuous))
    }

    private func signalsCard(_ report: MachOSignatureReport) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            Label("Research signals", systemImage: "magnifyingglass")
                .font(.headline)

            if report.warnings.isEmpty {
                Label("No structural warnings in the embedded signature.", systemImage: "checkmark.circle.fill")
                    .foregroundStyle(.green)
                    .font(.subheadline)
            } else {
                ForEach(report.warnings, id: \.self) { warning in
                    Label(warning, systemImage: "flag.fill")
                        .foregroundStyle(.orange)
                        .font(.subheadline)
                }
            }
        }
        .padding(16)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(.background, in: RoundedRectangle(cornerRadius: 18, style: .continuous))
    }

    private func evaluationCard(_ evaluation: CoreTrustEvaluation) -> some View {
        let success = evaluation.resultCode == 0

        return VStack(alignment: .leading, spacing: 9) {
            Label("CoreTrust result", systemImage: success ? "checkmark.seal.fill" : "xmark.seal.fill")
                .font(.headline)
                .foregroundStyle(success ? .green : .orange)

            LabeledContent("Runtime", value: evaluation.available ? "available" : "unavailable")
            LabeledContent("Result", value: evaluation.resultCode.map { String(format: "0x%08x", UInt32(bitPattern: $0)) } ?? "—")
            LabeledContent("Policy", value: evaluation.policyName)
            LabeledContent("CMS digest", value: evaluation.digestName)
            LabeledContent("Hash agility", value: evaluation.hashAgilityName)

            if let expectedDigestHex = evaluation.expectedDigestHex {
                Text("Expected digest")
                    .font(.caption.weight(.semibold))
                    .foregroundStyle(.secondary)

                Text(expectedDigestHex)
                    .font(.system(.caption2, design: .monospaced))
                    .textSelection(.enabled)
            }

            Text(evaluation.detail)
                .font(.caption)
                .foregroundStyle(.secondary)
        }
        .padding(16)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(.background, in: RoundedRectangle(cornerRadius: 18, style: .continuous))
    }

    private var researchScope: some View {
        HStack(alignment: .top, spacing: 10) {
            Image(systemName: "lock.shield")
                .foregroundStyle(.blue)

            Text("Research mode only: this screen inspects the app's own signature and asks CoreTrust to evaluate it. It does not patch signatures, bypass validation, execute exploit chains, or modify the device.")
                .font(.footnote)
                .foregroundStyle(.secondary)
        }
        .padding(15)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(.background, in: RoundedRectangle(cornerRadius: 18, style: .continuous))
    }

    private func infoCard(title: String, detail: String, icon: String, tint: Color) -> some View {
        HStack(alignment: .top, spacing: 11) {
            Image(systemName: icon)
                .foregroundStyle(tint)

            VStack(alignment: .leading, spacing: 3) {
                Text(title)
                    .font(.headline)
                Text(detail)
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
            }

            Spacer()
        }
        .padding(15)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(.background, in: RoundedRectangle(cornerRadius: 18, style: .continuous))
    }
}
