import Foundation

enum ScannerError: LocalizedError {
    case invalidURL
    case httpsRequired
    case requestFailed(String)

    var errorDescription: String? {
        switch self {
        case .invalidURL:
            return "Enter a valid URL."
        case .httpsRequired:
            return "For safety, VulnCheck accepts HTTPS targets only."
        case .requestFailed(let message):
            return message
        }
    }
}

final class ScannerEngine {
    private let session: URLSession

    init() {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.timeoutIntervalForRequest = 15
        configuration.timeoutIntervalForResource = 20
        configuration.httpAdditionalHeaders = [
            "User-Agent": "VulnCheck/0.1 (authorized-security-audit)"
        ]
        session = URLSession(configuration: configuration)
    }

    func scan(target: String) async throws -> ScanReport {
        guard let url = URL(string: target.trimmingCharacters(in: .whitespacesAndNewlines)),
              let scheme = url.scheme?.lowercased(),
              ["https", "http"].contains(scheme) else {
            throw ScannerError.invalidURL
        }

        guard scheme == "https" else {
            throw ScannerError.httpsRequired
        }

        var request = URLRequest(url: url)
        request.httpMethod = "HEAD"
        request.cachePolicy = .reloadIgnoringLocalCacheData
        request.setValue("https://vulncheck.local", forHTTPHeaderField: "Origin")

        do {
            let (_, response) = try await session.data(for: request)

            guard let httpResponse = response as? HTTPURLResponse else {
                throw ScannerError.requestFailed("The server returned a non-HTTP response.")
            }

            var findings = SecurityChecks.evaluate(response: httpResponse, requestedURL: url)
            findings.append(contentsOf: SecurityChecks.evaluateCORS(
                headers: stringHeaders(httpResponse.allHeaderFields)
            ))

            if let finalURL = httpResponse.url, finalURL.host != url.host {
                findings.append(Finding(
                    title: "Redirected to a different host",
                    severity: .info,
                    detail: "The request ended on a different host than requested.",
                    evidence: "(url.host ?? "?") → (finalURL.host ?? "?")",
                    remediation: "Verify that the cross-host redirect is intentional."
                ))
            }

            return ScanReport(
                target: url,
                finalURL: httpResponse.url,
                statusCode: httpResponse.statusCode,
                findings: findings,
                scannedAt: Date()
            )
        } catch let error as ScannerError {
            throw error
        } catch {
            throw ScannerError.requestFailed(error.localizedDescription)
        }
    }

    private func stringHeaders(_ input: [AnyHashable: Any]) -> [String: String] {
        var result: [String: String] = [:]
        for (key, value) in input {
            result[String(describing: key)] = String(describing: value)
        }
        return result
    }
}
