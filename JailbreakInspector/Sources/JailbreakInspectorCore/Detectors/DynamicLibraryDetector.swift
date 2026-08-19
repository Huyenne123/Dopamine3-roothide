import Foundation

#if canImport(Darwin)
import Darwin
#endif

public struct DynamicLibraryDetector: SecurityDetector {
    public let name = "Dynamic Library"

    public init() {}

    public static let suspiciousLibraryNames = [
        "substrate",
        "frida",
        "cycript",
        "cydia",
        "libsubstitute",
        "libweaker",
        "libhooker",
        "mbedtls",
        "mobile_substrate"
    ]

    public func scan() throws -> [DetectionResult] {
        #if canImport(Darwin)
        let imageCount = _dyld_image_count()
        var suspicious: [String] = []

        for index in 0..<imageCount {
            guard let namePointer = _dyld_get_image_name(index) else { continue }
            let imageName = String(cString: namePointer)
            let lowerName = imageName.lowercased()

            if DynamicLibraryDetector.suspiciousLibraryNames.contains(where: { lowerName.contains($0) }) {
                suspicious.append(imageName)
            }
        }

        if suspicious.isEmpty {
            return [
                DetectionResult(
                    id: "dynamic_library.none",
                    name: "No suspicious dynamic libraries detected",
                    category: .dynamicLibraries,
                    detected: false,
                    severity: 0,
                    explanation: "No loaded library names matched the suspicious set in this app configuration.",
                    technicalDetails: "Loaded images were inspected via dyld, but no high-risk library names were observed.",
                    whyItMatters: "A loaded library can be a sign of runtime tampering or injection, but a single library name is not definitive by itself.",
                    confidence: "Medium",
                    detector: name
                )
            ]
        }

        return suspicious.map { library in
            DetectionResult(
                id: "dynamic_library.\(library.lowercased().replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: ".", with: "_").replacingOccurrences(of: "-", with: "_"))",
                name: "Suspicious dynamic library: \(library)",
                category: .dynamicLibraries,
                detected: true,
                severity: 6,
                explanation: "A library name associated with jailbreak or hooking tooling was found in the current process.",
                technicalDetails: "Loaded image: \(library)",
                whyItMatters: "Loaded injection libraries are often associated with substrate, hooking, or persistence tooling, but the app itself may also include third-party frameworks.",
                confidence: "Medium",
                detector: name
            )
        }
        #else
        return [
            DetectionResult(
                id: "dynamic_library.unavailable",
                name: "Dynamic library inspection unavailable",
                category: .dynamicLibraries,
                detected: false,
                severity: 0,
                explanation: "This build does not support dyld inspection from the current platform, so the check is unavailable.",
                technicalDetails: "The app is not running on a Darwin-based platform with dyld available.",
                whyItMatters: "This is intentionally marked unavailable rather than treated as a clean result.",
                confidence: "Low",
                detector: name
            )
        ]
        #endif
    }
}
