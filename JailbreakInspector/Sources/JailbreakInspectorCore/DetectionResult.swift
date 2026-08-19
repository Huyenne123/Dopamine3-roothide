import Foundation

#if canImport(UIKit)
import UIKit
#endif

public enum DetectionCategory: String, Codable, CaseIterable {
    case jailbreak = "Jailbreak"
    case filesystem = "Filesystem"
    case runtime = "Runtime"
    case dynamicLibraries = "Dynamic Libraries"
    case sandbox = "Sandbox"
    case debugger = "Debugger"
    case integrity = "Integrity"
    case environment = "Environment"
}

public struct DetectionResult: Codable, Identifiable, Equatable {
    public let id: String
    public let name: String
    public let category: DetectionCategory
    public let detected: Bool
    public let severity: Int
    public let explanation: String
    public let technicalDetails: String?
    public let whyItMatters: String
    public let confidence: String
    public let detector: String

    public init(
        id: String,
        name: String,
        category: DetectionCategory,
        detected: Bool,
        severity: Int,
        explanation: String,
        technicalDetails: String? = nil,
        whyItMatters: String,
        confidence: String = "Medium",
        detector: String
    ) {
        self.id = id
        self.name = name
        self.category = category
        self.detected = detected
        self.severity = severity
        self.explanation = explanation
        self.technicalDetails = technicalDetails
        self.whyItMatters = whyItMatters
        self.confidence = confidence
        self.detector = detector
    }
}

public struct DeviceInfo: Codable, Equatable {
    public let model: String
    public let systemVersion: String

    public static var current: DeviceInfo {
        #if canImport(UIKit)
        let model = UIDevice.current.model
        #else
        let model = "Unknown simulator or host"
        #endif

        return DeviceInfo(
            model: model,
            systemVersion: ProcessInfo.processInfo.operatingSystemVersionString
        )
    }
}

public struct SecurityScan: Codable, Equatable {
    public let timestamp: String
    public let device: DeviceInfo
    public let score: Int
    public let assessment: String
    public let detections: [DetectionResult]
    public let detectorErrors: [String]

    public init(
        timestamp: String,
        device: DeviceInfo,
        score: Int,
        assessment: String,
        detections: [DetectionResult],
        detectorErrors: [String]
    ) {
        self.timestamp = timestamp
        self.device = device
        self.score = score
        self.assessment = assessment
        self.detections = detections
        self.detectorErrors = detectorErrors
    }

    public func jsonData() throws -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        return try encoder.encode(self)
    }

    public func jsonString() throws -> String {
        let data = try jsonData()
        return String(decoding: data, as: UTF8.self)
    }
}

public enum DetectorError: LocalizedError {
    case failed(String)

    public var errorDescription: String? {
        switch self {
        case .failed(let message):
            return message
        }
    }
}
