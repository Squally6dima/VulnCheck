import XCTest
@testable import VulnCheck

final class SecurityChecksTests: XCTestCase {
    func testMissingSecurityHeadersAreDetected() throws {
        let url = try XCTUnwrap(URL(string: "https://example.com"))
        let response = try XCTUnwrap(
            HTTPURLResponse(
                url: url,
                statusCode: 200,
                httpVersion: "HTTP/1.1",
                headerFields: [
                    "Content-Type": "text/html",
                    "Server": "test-server"
                ]
            )
        )

        let findings = SecurityChecks.evaluate(response: response, requestedURL: url)

        XCTAssertTrue(findings.contains { $0.title == "HSTS is missing" })
        XCTAssertTrue(findings.contains { $0.title == "Content Security Policy is missing" })
        XCTAssertTrue(findings.contains { $0.title == "Server banner exposed" })
    }

    func testCORSWildcardWithCredentialsIsHigh() {
        let findings = SecurityChecks.evaluateCORS(headers: [
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Credentials": "true"
        ])

        XCTAssertEqual(findings.first?.severity, .high)
    }
}
