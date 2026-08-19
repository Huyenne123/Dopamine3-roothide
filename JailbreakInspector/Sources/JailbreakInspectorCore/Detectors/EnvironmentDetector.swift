import Foundation

public struct EnvironmentDetector: SecurityDetector {
    public let name = "Environment"

    public init() {}

    public func scan() throws -> [DetectionResult] {
        let suspiciousKeys = [
            "DYLD_INSERT_LIBRARIES",
            "DYLD_PRINT_STATISTICS",
            "JAILBREAK",
            "JB_ROOT",
            "CFFIXED_USER_HOME"
        ]

        let environment = ProcessInfo.processInfo.environment
        let matches = suspiciousKeys.filter { key in
            environment[key] != nil && !(environment[key] ?? "").isEmpty
        }

        if matches.isEmpty {
            return [
                DetectionResult(
                    id: "environment.none",
                    name: "No suspicious environment variables detected",
                    category: .environment,
                    detected: false,
                    severity: 0,
                    explanation: "No suspicious environment variables were found in the current process.",
                    technicalDetails: "Environment values were reviewed for common jailbreak or injection indicators.",
                    whyItMatters: "Environment variables are easy to tamper with, so they are considered supplementary evidence rather than proof.",
                    confidence: "Low",
                    detector: name
                )
            ]
        }

        return matches.map { key in
            let value = environment[key] ?? ""
            return DetectionResult(
                id: "environment.\(key.lowercased())",
                name: "Environment variable \(key) present",
                category: .environment,
                detected: true,
                severity: 3,
                explanation: "A suspicious runtime environment variable commonly used by modified or injected environments was found.",
                technicalDetails: "Key: \(key)\nValue: \(value)",
                whyItMatters: "Environment variables are simple to manipulate, so they should only be treated as supporting evidence.",
                confidence: "Low",
                detector: name
            )
        }
    }
}
