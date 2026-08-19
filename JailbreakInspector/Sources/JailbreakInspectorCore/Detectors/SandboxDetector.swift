import Foundation

public struct SandboxDetector: SecurityDetector {
    public let name = "Sandbox"

    public init() {}

    public func scan() throws -> [DetectionResult] {
        let suspiciousPaths = [
            "/private",
            "/var",
            "/usr/lib",
            "/Applications",
            "/System"
        ]

        let accessiblePaths = suspiciousPaths.filter { FileManager.default.isWritableFile(atPath: $0) }

        if accessiblePaths.isEmpty {
            return [
                DetectionResult(
                    id: "sandbox.clean",
                    name: "Sandbox appears intact",
                    category: .sandbox,
                    detected: false,
                    severity: 0,
                    explanation: "No suspicious write access was observed outside the app's normal safe working area.",
                    technicalDetails: "Checked writeability for common system-restricted locations using temporary-safe operations.",
                    whyItMatters: "Open write access to protected system paths is highly suspicious for a standard app sandbox.",
                    confidence: "Medium",
                    detector: name
                )
            ]
        }

        return accessiblePaths.map { path in
            DetectionResult(
                id: "sandbox.\(path.replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: ".", with: "_"))",
                name: "Writable system path: \(path)",
                category: .sandbox,
                detected: true,
                severity: 4,
                explanation: "The app appears to be able to modify a system-restricted path that should normally be sandbox-protected.",
                technicalDetails: "Writable path: \(path)",
                whyItMatters: "Unexpected write access can mean the app is running in a modified environment or the sandbox is weakened.",
                confidence: "Medium",
                detector: name
            )
        }
    }
}
