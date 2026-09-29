import Foundation

struct CodeDirectoryRecord: Identifiable {
    let id = UUID()
    let index: Int
    let length: Int
    let version: UInt32
    let flags: UInt32
    let specialSlots: UInt32
    let codeSlots: UInt32
    let codeLimit: UInt64
    let hashSize: UInt8
    let hashType: UInt8
    let pageSize: UInt8

    var hashTypeName: String {
        switch hashType {
        case 1: return "SHA-1"
        case 2: return "SHA-256"
        case 3: return "SHA-256 truncated"
        case 4: return "SHA-384"
        case 5: return "SHA-512"
        default: return "0x\(String(hashType, radix: 16))"
        }
    }

    var versionName: String {
        String(format: "0x%08X", version)
    }
}

struct MachOSignatureReport {
    let executablePath: String
    let signatureOffset: Int
    let signatureSize: Int
    let cms: [UInt8]
    let codeDirectoryBlobs: [[UInt8]]
    let codeDirectories: [CodeDirectoryRecord]
    let warnings: [String]

    var hasCMS: Bool { !cms.isEmpty }
    var hasMultipleCodeDirectories: Bool { codeDirectories.count > 1 }
}

enum MachOSignatureParser {
    private static let lcCodeSignature: UInt32 = 0x1D
    private static let superBlobMagic: UInt32 = 0xFADE0CC0
    private static let codeDirectoryMagic: UInt32 = 0xFADE0C02
    private static let blobHeaderSize = 8

    static func analyze(url: URL) throws -> MachOSignatureReport {
        let data = try Data(contentsOf: url)
        let bytes = [UInt8](data)

        guard bytes.count >= 32 else {
            throw ParserError.invalidMachO("Executable is too small to be a 64-bit Mach-O.")
        }

        let magic = readU32(bytes, at: 0)
        guard magic == 0xFEEDFACF || magic == 0xCAFEBABF else {
            throw ParserError.invalidMachO("Unsupported Mach-O magic: 0x\(String(magic, radix: 16)).")
        }

        let isFatHeader = magic == 0xCAFEBABF
        if isFatHeader {
            throw ParserError.invalidMachO("Fat binaries are not supported in the on-device baseline yet.")
        }

        let ncmds = Int(readU32(bytes, at: 16))
        var commandOffset = 32
        var signatureOffset = 0
        var signatureSize = 0

        for _ in 0..<ncmds {
            guard commandOffset + 8 <= bytes.count else {
                throw ParserError.invalidMachO("Load command table is truncated.")
            }

            let cmd = readU32(bytes, at: commandOffset)
            let cmdSize = Int(readU32(bytes, at: commandOffset + 4))

            guard cmdSize >= 8, commandOffset + cmdSize <= bytes.count else {
                throw ParserError.invalidMachO("Malformed load command size.")
            }

            if cmd == lcCodeSignature && cmdSize >= 16 {
                signatureOffset = Int(readU32(bytes, at: commandOffset + 8))
                signatureSize = Int(readU32(bytes, at: commandOffset + 12))
                break
            }

            commandOffset += cmdSize
        }

        guard signatureOffset > 0, signatureSize > 0,
              signatureOffset + signatureSize <= bytes.count else {
            throw ParserError.noCodeSignature
        }

        let signature = Array(bytes[signatureOffset..<(signatureOffset + signatureSize)])
        guard signature.count >= 12, readU32(signature, at: 0) == superBlobMagic else {
            throw ParserError.invalidSignature("Embedded signature is not a valid SuperBlob.")
        }

        let count = Int(readU32(signature, at: 8))
        guard 12 + count * 8 <= signature.count else {
            throw ParserError.invalidSignature("SuperBlob index is truncated.")
        }

        var cms: [UInt8] = []
        var codeDirectoryBlobs: [[UInt8]] = []
        var codeDirectories: [CodeDirectoryRecord] = []
        var warnings: [String] = []

        for index in 0..<count {
            let base = 12 + index * 8
            let type = readU32(signature, at: base)
            let offset = Int(readU32(signature, at: base + 4))

            guard offset + blobHeaderSize <= signature.count else {
                warnings.append("Blob #\(index) has an out-of-bounds header.")
                continue
            }

            let blobMagic = readU32(signature, at: offset)
            let blobLength = Int(readU32(signature, at: offset + 4))

            guard blobLength >= blobHeaderSize, offset + blobLength <= signature.count else {
                warnings.append("Blob #\(index) has an invalid length.")
                continue
            }

            let blob = Array(signature[offset..<(offset + blobLength)])

            if type == 5 {
                cms = Array(blob.dropFirst(blobHeaderSize))
            }

            if blobMagic == codeDirectoryMagic, let record = parseCodeDirectory(blob, index: codeDirectoryBlobs.count) {
                codeDirectoryBlobs.append(blob)
                codeDirectories.append(record)
            }
        }

        if codeDirectories.isEmpty {
            warnings.append("No CodeDirectory blob was found.")
        }

        if codeDirectories.count > 1 {
            warnings.append("Multiple CodeDirectory blobs are present. This is not itself a vulnerability, but it is a relevant signature-validation surface.")
        }

        if codeDirectories.contains(where: { $0.hashType == 1 }) &&
            codeDirectories.contains(where: { $0.hashType == 2 || $0.hashType == 3 }) {
            warnings.append("SHA-1 and SHA-256 CodeDirectories coexist. Review hash-selection and hash-agility behavior on the target OS.")
        }

        if cms.isEmpty {
            warnings.append("CMS signature blob was not found.")
        }

        return MachOSignatureReport(
            executablePath: url.path,
            signatureOffset: signatureOffset,
            signatureSize: signatureSize,
            cms: cms,
            codeDirectoryBlobs: codeDirectoryBlobs,
            codeDirectories: codeDirectories,
            warnings: warnings
        )
    }

    private static func parseCodeDirectory(_ blob: [UInt8], index: Int) -> CodeDirectoryRecord? {
        guard blob.count >= 40 else { return nil }

        return CodeDirectoryRecord(
            index: index,
            length: Int(readU32(blob, at: 4)),
            version: readU32(blob, at: 8),
            flags: readU32(blob, at: 12),
            specialSlots: readU32(blob, at: 24),
            codeSlots: readU32(blob, at: 28),
            codeLimit: UInt64(readU32(blob, at: 32)),
            hashSize: blob[36],
            hashType: blob[37],
            pageSize: blob[39]
        )
    }

    private static func readU32(_ bytes: [UInt8], at offset: Int) -> UInt32 {
        UInt32(bytes[offset]) |
        (UInt32(bytes[offset + 1]) << 8) |
        (UInt32(bytes[offset + 2]) << 16) |
        (UInt32(bytes[offset + 3]) << 24)
    }

    enum ParserError: LocalizedError {
        case invalidMachO(String)
        case noCodeSignature
        case invalidSignature(String)

        var errorDescription: String? {
            switch self {
            case .invalidMachO(let message), .invalidSignature(let message):
                return message
            case .noCodeSignature:
                return "No embedded code signature was found."
            }
        }
    }
}
