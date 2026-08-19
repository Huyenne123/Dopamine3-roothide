import XCTest
@testable import JailbreakInspectorCore

final class JailbreakInspectorCoreTests: XCTestCase {
    func testNoFindings() throws {
        let score = ScoreEngine.computeScore(for: [])
        XCTAssertEqual(score, 0)
        XCTAssertEqual(ScoreEngine.assessment(for: score), "Probably clean")
    }

    func testOneLowSeverityFinding() throws {
        let detection = DetectionResult(
            id: "low.1",
            name: "Low severity issue",
            category: .environment,
            detected: true,
            severity: 1,
            explanation: "A low-severity finding.",
            whyItMatters: "It should be considered but not treated as definitive.",
            detector: "Test"
        )

        let score = ScoreEngine.computeScore(for: [detection])
        XCTAssertEqual(score, 1)
        XCTAssertEqual(ScoreEngine.assessment(for: score), "Probably clean")
    }

    func testMultipleFindings() throws {
        let detections = [
            DetectionResult(id: "multi.1", name: "One", category: .filesystem, detected: true, severity: 2, explanation: "A", whyItMatters: "B", detector: "Test"),
            DetectionResult(id: "multi.2", name: "Two", category: .runtime, detected: true, severity: 3, explanation: "C", whyItMatters: "D", detector: "Test"),
            DetectionResult(id: "multi.3", name: "Three", category: .sandbox, detected: true, severity: 5, explanation: "E", whyItMatters: "F", detector: "Test")
        ]

        XCTAssertEqual(ScoreEngine.computeScore(for: detections), 10)
        XCTAssertEqual(ScoreEngine.numberOfFindings(for: detections), 3)
    }

    func testHighSeverityFindings() throws {
        let detections = [
            DetectionResult(id: "high.1", name: "High", category: .jailbreak, detected: true, severity: 8, explanation: "A", whyItMatters: "B", detector: "Test"),
            DetectionResult(id: "high.2", name: "Higher", category: .jailbreak, detected: true, severity: 10, explanation: "C", whyItMatters: "D", detector: "Test")
        ]

        let score = ScoreEngine.computeScore(for: detections)
        XCTAssertEqual(score, 18)
        XCTAssertEqual(ScoreEngine.assessment(for: score), "Strong evidence of modification")
    }

    func testDetectorFailure() throws {
        struct FailingDetector: SecurityDetector {
            let name = "Failing detector"

            func scan() throws -> [DetectionResult] {
                throw DetectorError.failed("simulated detector failure")
            }
        }

        let scan = SecurityScanner().runScan(with: [FailingDetector()])
        XCTAssertEqual(scan.detectorErrors.count, 1)
        XCTAssertTrue(scan.detectorErrors[0].contains("Failing detector"))
        XCTAssertEqual(scan.score, 0)
    }

    func testDuplicateFindings() throws {
        let first = DetectionResult(id: "dup.1", name: "Duplicate", category: .filesystem, detected: true, severity: 4, explanation: "A", whyItMatters: "B", detector: "Test")
        let second = DetectionResult(id: "dup.1", name: "Duplicate", category: .filesystem, detected: true, severity: 4, explanation: "A", whyItMatters: "B", detector: "Test")

        let score = ScoreEngine.computeScore(for: [first, second])
        XCTAssertEqual(score, 4)
    }

    func testJSONExport() throws {
        let detection = DetectionResult(
            id: "json.1",
            name: "JSON issue",
            category: .filesystem,
            detected: true,
            severity: 5,
            explanation: "Example detection.",
            whyItMatters: "This is used for export validation.",
            detector: "Test"
        )

        let scan = SecurityScan(
            timestamp: "2026-08-19T00:00:00Z",
            device: DeviceInfo(model: "TestDevice", systemVersion: "17.0"),
            score: 5,
            assessment: "Suspicious",
            detections: [detection],
            detectorErrors: []
        )

        let json = try scan.jsonString()
        XCTAssertTrue(json.contains("\"score\": 5"))
        XCTAssertTrue(json.contains("\"detections\""))
        XCTAssertTrue(json.contains("\"device\""))
    }

    func testScoreCalculation() throws {
        let detections = [
            DetectionResult(id: "calc.1", name: "A", category: .filesystem, detected: true, severity: 2, explanation: "A", whyItMatters: "B", detector: "Test"),
            DetectionResult(id: "calc.2", name: "B", category: .environment, detected: true, severity: 3, explanation: "C", whyItMatters: "D", detector: "Test"),
            DetectionResult(id: "calc.3", name: "C", category: .runtime, detected: false, severity: 7, explanation: "E", whyItMatters: "F", detector: "Test")
        ]

        XCTAssertEqual(ScoreEngine.computeScore(for: detections), 5)
        let totals = ScoreEngine.categoryTotals(for: detections)
        XCTAssertEqual(totals[.filesystem], 1)
        XCTAssertEqual(totals[.environment], 1)
        XCTAssertEqual(totals[.runtime], nil)
    }
}
