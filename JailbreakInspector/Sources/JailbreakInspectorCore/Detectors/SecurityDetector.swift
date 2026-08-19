import Foundation

public protocol SecurityDetector {
    var name: String { get }
    func scan() throws -> [DetectionResult]
}

public final class SecurityScanner {
    public init() {}

    public func runScan() -> SecurityScan {
        let detectors: [any SecurityDetector] = [
            IOSSecuritySuiteDetector(),
            FilesystemDetector(),
            DynamicLibraryDetector(),
            SandboxDetector(),
            URLSchemeDetector(),
            EnvironmentDetector(),
            IntegrityDetector()
        ]
        return runScan(with: detectors)
    }

    public func runScan(with detectors: [any SecurityDetector]) -> SecurityScan {
        var detections: [DetectionResult] = []
        var detectorErrors: [String] = []

        for detector in detectors {
            do {
                let results = try detector.scan()
                detections.append(contentsOf: results)
            } catch {
                detectorErrors.append("\(detector.name) failed: \(error.localizedDescription)")
                detections.append(
                    DetectionResult(
                        id: "detector.\(detector.name.lowercased().replacingOccurrences(of: " ", with: "_"))_unavailable",
                        name: "\(detector.name) unavailable",
                        category: .integrity,
                        detected: false,
                        severity: 0,
                        explanation: "This detector failed during execution and was skipped rather than crashing the scan.",
                        technicalDetails: error.localizedDescription,
                        whyItMatters: "Partial results are still useful, but the missing signal should be treated as unknown rather than definitive.",
                        confidence: "Low",
                        detector: detector.name
                    )
                )
            }
        }

        let score = ScoreEngine.computeScore(for: detections)
        let assessment = ScoreEngine.assessment(for: score)

        return SecurityScan(
            timestamp: ISO8601DateFormatter().string(from: Date()),
            device: DeviceInfo.current,
            score: score,
            assessment: assessment,
            detections: detections,
            detectorErrors: detectorErrors
        )
    }
}
