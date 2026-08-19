import Foundation

#if canImport(UIKit)
import UIKit
#endif

public struct URLSchemeDetector: SecurityDetector {
    public let name = "URL Schemes"

    public init() {}

    public func scan() throws -> [DetectionResult] {
        let suspiciousSchemes = ["cydia", "sileo", "zbra", "filza", "undecimus"]
        var results: [DetectionResult] = []

        for scheme in suspiciousSchemes {
            let detected = canOpen(urlScheme: scheme)
            let id = "url_scheme.\(scheme)"

            if detected {
                results.append(
                    DetectionResult(
                        id: id,
                        name: "\(scheme) URL scheme detected",
                        category: .filesystem,
                        detected: true,
                        severity: 3,
                        explanation: "The app can open a scheme commonly associated with package managers or jailbreak tooling.",
                        technicalDetails: "Scheme: \(scheme)://",
                        whyItMatters: "Jailbreak-related URL schemes are powerful signals but can also be present in unrelated or developer-only environments.",
                        confidence: "Low",
                        detector: name
                    )
                )
            } else {
                results.append(
                    DetectionResult(
                        id: id + "_clear",
                        name: "\(scheme) URL scheme not detected",
                        category: .filesystem,
                        detected: false,
                        severity: 0,
                        explanation: "The app did not report the scheme as present in the current environment.",
                        technicalDetails: "Scheme: \(scheme)://",
                        whyItMatters: "This is a useful negative signal, but URL scheme detection can miss installed packages or represent a false negative.",
                        confidence: "Low",
                        detector: name
                    )
                )
            }
        }

        return results
    }

    private func canOpen(urlScheme scheme: String) -> Bool {
        #if canImport(UIKit)
        guard let url = URL(string: "\(scheme)://") else {
            return false
        }
        return UIApplication.shared.canOpenURL(url)
        #else
        return false
        #endif
    }
}
