import Foundation

public struct FilesystemDetector: SecurityDetector {
    public let name = "Filesystem"

    public init() {}

    public func scan() throws -> [DetectionResult] {
        let manager = FileManager.default
        let suspiciousPaths = [
            "/var/jb",
            "/Applications/Cydia.app",
            "/Applications/Sileo.app",
            "/Applications/Zebra.app",
            "/Library/MobileSubstrate",
            "/usr/libexec/cydia",
            "/etc/apt",
            "/private/var/lib/apt",
            "/var/lib/apt",
            "/private/preboot"
        ]

        var results: [DetectionResult] = []

        for path in suspiciousPaths {
            let exists = manager.fileExists(atPath: path)
            let id = "filesystem.\(path.replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: ".", with: "_").replacingOccurrences(of: "-", with: "_"))"

            if exists {
                results.append(
                    DetectionResult(
                        id: id,
                        name: "\(path) detected",
                        category: .filesystem,
                        detected: true,
                        severity: path == "/var/jb" ? 5 : 4,
                        explanation: "A jailbreak-related filesystem artifact was found on disk.",
                        technicalDetails: "Path: \(path)\nExists: true",
                        whyItMatters: "Jailbreaks often leave suspicious files or application bundles behind, but some can be legitimately present or remnant artifacts.",
                        confidence: "Medium",
                        detector: name
                    )
                )
            } else {
                results.append(
                    DetectionResult(
                        id: id,
                        name: "\(path) not detected",
                        category: .filesystem,
                        detected: false,
                        severity: 0,
                        explanation: "This known jailbreak artifact was not found during the scan.",
                        technicalDetails: "Path: \(path)\nExists: false",
                        whyItMatters: "This does not prove the device is clean, but it reduces the evidence of a traditional jailbreak layout.",
                        confidence: "Medium",
                        detector: name
                    )
                )
            }
        }

        return results
    }
}
