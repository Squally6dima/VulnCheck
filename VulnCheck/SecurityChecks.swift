import Foundation

enum SecurityChecks {
    static func evaluate(response: HTTPURLResponse, requestedURL: URL) -> [Finding] {
        var findings: [Finding] = []
        let headers = normalizedHeaders(response.allHeaderFields)

        if requestedURL.scheme?.lowercased() != "https" {
            findings.append(Finding(
                title: "Unencrypted HTTP target",
                severity: .high,
                detail: "The requested URL uses HTTP instead of HTTPS.",
                evidence: requestedURL.absoluteString,
                remediation: "Use HTTPS and redirect HTTP traffic to HTTPS."
            ))
        }

        if requestedURL.scheme?.lowercased() == "https" &&
            headers["strict-transport-security"] == nil {
            findings.append(Finding(
                title: "HSTS is missing",
                severity: .medium,
                detail: "The HTTPS response does not advertise Strict-Transport-Security.",
                evidence: "Strict-Transport-Security: <missing>",
                remediation: "Consider enabling HSTS after confirming the entire site is HTTPS-only."
            ))
        }

        if headers["content-security-policy"] == nil {
            findings.append(Finding(
                title: "Content Security Policy is missing",
                severity: .medium,
                detail: "No Content-Security-Policy header was observed.",
                evidence: "Content-Security-Policy: <missing>",
                remediation: "Define a restrictive CSP appropriate for the application."
            ))
        }

        if headers["x-content-type-options"]?.lowercased() != "nosniff" {
            findings.append(Finding(
                title: "X-Content-Type-Options is missing or weak",
                severity: .low,
                detail: "The response does not explicitly use X-Content-Type-Options: nosniff.",
                evidence: "X-Content-Type-Options: (headers["x-content-type-options"] ?? "<missing>")",
                remediation: "Set X-Content-Type-Options: nosniff."
            ))
        }

        if headers["referrer-policy"] == nil {
            findings.append(Finding(
                title: "Referrer-Policy is missing",
                severity: .low,
                detail: "No Referrer-Policy header was observed.",
                evidence: "Referrer-Policy: <missing>",
                remediation: "Set a suitable Referrer-Policy for the application."
            ))
        }

        if headers["permissions-policy"] == nil {
            findings.append(Finding(
                title: "Permissions-Policy is missing",
                severity: .low,
                detail: "No Permissions-Policy header was observed.",
                evidence: "Permissions-Policy: <missing>",
                remediation: "Explicitly disable browser capabilities the application does not need."
            ))
        }

        let hasFrameProtection = headers["x-frame-options"] != nil ||
            (headers["content-security-policy"]?.lowercased().contains("frame-ancestors") ?? false)

        if !hasFrameProtection {
            findings.append(Finding(
                title: "Clickjacking protection is missing",
                severity: .low,
                detail: "Neither X-Frame-Options nor CSP frame-ancestors was observed.",
                evidence: "X-Frame-Options: <missing>; CSP frame-ancestors: <missing>",
                remediation: "Use CSP frame-ancestors and/or X-Frame-Options as appropriate."
            ))
        }

        if let server = headers["server"], !server.isEmpty {
            findings.append(Finding(
                title: "Server banner exposed",
                severity: .info,
                detail: "The response exposes a Server header.",
                evidence: "Server: (server)",
                remediation: "Minimize unnecessary server/version disclosure where practical."
            ))
        }

        if let poweredBy = headers["x-powered-by"], !poweredBy.isEmpty {
            findings.append(Finding(
                title: "Technology banner exposed",
                severity: .low,
                detail: "The response exposes an X-Powered-By header.",
                evidence: "X-Powered-By: (poweredBy)",
                remediation: "Remove unnecessary framework/runtime identification headers."
            ))
        }

        if let setCookie = headers["set-cookie"] {
            let cookie = setCookie.lowercased()

            if !cookie.contains("secure") {
                findings.append(Finding(
                    title: "Cookie without Secure attribute",
                    severity: .medium,
                    detail: "A Set-Cookie response was observed without Secure.",
                    evidence: "Set-Cookie: (setCookie)",
                    remediation: "For sensitive cookies, add the Secure attribute."
                ))
            }

            if !cookie.contains("httponly") {
                findings.append(Finding(
                    title: "Cookie without HttpOnly attribute",
                    severity: .medium,
                    detail: "A Set-Cookie response was observed without HttpOnly.",
                    evidence: "Set-Cookie: (setCookie)",
                    remediation: "Use HttpOnly for cookies that do not need JavaScript access."
                ))
            }

            if !cookie.contains("samesite=") {
                findings.append(Finding(
                    title: "Cookie without SameSite attribute",
                    severity: .low,
                    detail: "A Set-Cookie response was observed without SameSite.",
                    evidence: "Set-Cookie: (setCookie)",
                    remediation: "Set an explicit SameSite policy appropriate to the application."
                ))
            }
        }

        return findings
    }

    static func evaluateCORS(headers: [String: String]) -> [Finding] {
        let normalized = normalizedHeaders(headers)

        guard let origin = normalized["access-control-allow-origin"] else {
            return []
        }

        if origin == "*" && normalized["access-control-allow-credentials"]?.lowercased() == "true" {
            return [Finding(
                title: "CORS wildcard with credentials",
                severity: .high,
                detail: "The response combines wildcard origin with credentials enabled.",
                evidence: "Access-Control-Allow-Origin: *; Access-Control-Allow-Credentials: true",
                remediation: "Allow only trusted origins for credentialed cross-origin requests."
            )]
        }

        if origin == "*" {
            return [Finding(
                title: "CORS allows every origin",
                severity: .low,
                detail: "The response permits cross-origin requests from any origin.",
                evidence: "Access-Control-Allow-Origin: *",
                remediation: "If access is not intentionally public, restrict allowed origins."
            )]
        }

        return []
    }

    private static func normalizedHeaders(_ input: [AnyHashable: Any]) -> [String: String] {
        var result: [String: String] = [:]
        for (key, value) in input {
            result[String(describing: key).lowercased()] = String(describing: value)
        }
        return result
    }

    private static func normalizedHeaders(_ input: [String: String]) -> [String: String] {
        Dictionary(uniqueKeysWithValues: input.map { ($0.key.lowercased(), $0.value) })
    }
}
