import Foundation

public enum ScoreAssessment: String {
    case probablyClean = "Probably clean"
    case suspicious = "Suspicious"
    case likelyModified = "Likely modified"
    case strongEvidence = "Strong evidence of modification"
}

public final class ScoreEngine {
    public static func computeScore(for detections: [DetectionResult]) -> Int {
        deduplicate(detections)
            .filter(\.detected)
            .reduce(0) { partialResult, detection in
                partialResult + max(0, detection.severity)
            }
    }

    public static func assessment(for score: Int) -> String {
        switch score {
        case 0...2:
            return ScoreAssessment.probablyClean.rawValue
        case 3...5:
            return ScoreAssessment.suspicious.rawValue
        case 6...9:
            return ScoreAssessment.likelyModified.rawValue
        default:
            return ScoreAssessment.strongEvidence.rawValue
        }
    }

    public static func numberOfFindings(for detections: [DetectionResult]) -> Int {
        deduplicate(detections).filter(\.detected).count
    }

    public static func categoryTotals(for detections: [DetectionResult]) -> [DetectionCategory: Int] {
        var totals: [DetectionCategory: Int] = [:]
        for detection in deduplicate(detections).filter(\.detected) {
            totals[detection.category, default: 0] += 1
        }
        return totals
    }

    private static func deduplicate(_ detections: [DetectionResult]) -> [DetectionResult] {
        var unique: [String: DetectionResult] = [:]
        for detection in detections {
            unique[detection.id] = detection
        }
        return Array(unique.values)
    }
}
