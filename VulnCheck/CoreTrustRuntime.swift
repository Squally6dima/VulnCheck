import Foundation
import Darwin

struct CoreTrustEvaluation {
    let available: Bool
    let resultCode: Int32?
    let policyFlags: UInt64?
    let cmsDigestType: UInt32?
    let hashAgilityDigestType: UInt32?
    let expectedDigestHex: String?
    let detail: String

    var policyName: String {
        guard let flags = policyFlags else { return "—" }

        var names: [String] = []
        if flags & (1 << 8) != 0 { names.append("iPhone App Store") }
        if flags & (1 << 9) != 0 { names.append("iPhone App Development") }
        if flags & (1 << 7) != 0 { names.append("iPhone Developer") }
        if flags & (1 << 16) != 0 { names.append("iPhone Distribution") }
        if flags & (1 << 14) != 0 { names.append("TestFlight Production") }
        if flags & (1 << 15) != 0 { names.append("TestFlight Development") }
        return names.isEmpty ? String(format: "0x%llx", flags) : names.joined(separator: ", ")
    }

    var digestName: String {
        switch cmsDigestType {
        case 1: return "SHA-1"
        case 2: return "SHA-224"
        case 4: return "SHA-256"
        case 8: return "SHA-384"
        case 16: return "SHA-512"
        default: return "unknown"
        }
    }

    var hashAgilityName: String {
        switch hashAgilityDigestType {
        case 1: return "SHA-1"
        case 2: return "SHA-224"
        case 4: return "SHA-256"
        case 8: return "SHA-384"
        case 16: return "SHA-512"
        default: return "none"
        }
    }
}

enum CoreTrustRuntime {
    private typealias EvaluateFunction = @convention(c) (
        UnsafePointer<UInt8>?, Int,
        UnsafePointer<UInt8>?, Int,
        Bool,
        UnsafeMutablePointer<UnsafePointer<UInt8>?>?,
        UnsafeMutablePointer<Int>?,
        UnsafeMutablePointer<UInt64>?,
        UnsafeMutablePointer<UInt32>?,
        UnsafeMutablePointer<UInt32>?,
        UnsafeMutablePointer<UnsafePointer<UInt8>?>?,
        UnsafeMutablePointer<Int>?
    ) -> Int32

    static func evaluate(cms: [UInt8], codeDirectory: [UInt8]) -> CoreTrustEvaluation {
        let frameworkPath = "/System/Library/PrivateFrameworks/MobileInBoxUpdate.framework/MobileInBoxUpdate"

        guard let handle = dlopen(frameworkPath, RTLD_NOW | RTLD_LOCAL) else {
            return CoreTrustEvaluation(
                available: false,
                resultCode: nil,
                policyFlags: nil,
                cmsDigestType: nil,
                hashAgilityDigestType: nil,
                expectedDigestHex: nil,
                detail: "MobileInBoxUpdate/CoreTrust runtime is not exposed to this process."
            )
        }

        defer { dlclose(handle) }

        guard let rawSymbol = dlsym(handle, "CTEvaluateAMFICodeSignatureCMS") else {
            return CoreTrustEvaluation(
                available: false,
                resultCode: nil,
                policyFlags: nil,
                cmsDigestType: nil,
                hashAgilityDigestType: nil,
                expectedDigestHex: nil,
                detail: "CTEvaluateAMFICodeSignatureCMS was not exported by MobileInBoxUpdate."
            )
        }

        let evaluate = unsafeBitCast(rawSymbol, to: EvaluateFunction.self)

        var leaf: UnsafePointer<UInt8>?
        var leafLength = 0
        var policy: UInt64 = 0
        var cmsDigest: UInt32 = 0
        var agilityDigest: UInt32 = 0
        var digest: UnsafePointer<UInt8>?
        var digestLength = 0

        let result: Int32 = cms.withUnsafeBufferPointer { cmsBuffer in
            codeDirectory.withUnsafeBufferPointer { codeDirectoryBuffer in
                evaluate(
                    cmsBuffer.baseAddress,
                    cmsBuffer.count,
                    codeDirectoryBuffer.baseAddress,
                    codeDirectoryBuffer.count,
                    false,
                    &leaf,
                    &leafLength,
                    &policy,
                    &cmsDigest,
                    &agilityDigest,
                    &digest,
                    &digestLength
                )
            }
        }

        let digestHex: String? = {
            guard let digest, digestLength > 0 else { return nil }
            return (0..<digestLength).map { String(format: "%02x", digest[$0]) }.joined()
        }()

        return CoreTrustEvaluation(
            available: true,
            resultCode: result,
            policyFlags: policy,
            cmsDigestType: cmsDigest,
            hashAgilityDigestType: agilityDigest,
            expectedDigestHex: digestHex,
            detail: result == 0 ? "CoreTrust accepted the CMS/CodeDirectory pair." : String(format: "CoreTrust returned error 0x%08x.", UInt32(bitPattern: result))
        )
    }
}
