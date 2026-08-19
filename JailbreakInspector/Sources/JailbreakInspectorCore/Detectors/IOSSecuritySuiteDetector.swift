import Foundation

#if canImport(IOSSecuritySuite)
import IOSSecuritySuite
#endif

public struct IOSSecuritySuiteDetector: SecurityDetector {
    public let name = "IOSSecuritySuite"

    public init() {}

    public func scan() throws -> [DetectionResult] {
        #if canImport(IOSSecuritySuite)
        var results: [DetectionResult] = []

        let jailbreakStatus = IOSSecuritySuite.amIJailbrokenWithFailedChecks()
        if jailbreakStatus.jailbroken {
            results.append(
                DetectionResult(
                    id: "iossecuritysuite.jailbreak",
                    name: "IOSSecuritySuite jailbreak detection triggered",
                    category: .jailbreak,
                    detected: true,
                    severity: 8,
                    explanation: "IOSSecuritySuite reported evidence of a jailbreak or suspicious jailbreak-related checks.",
                    technicalDetails: jailbreakStatus.failedChecks.map { String(describing: $0.check) }.joined(separator: ", "),
                    whyItMatters: "A jailbreak detector can be bypassed, but it is still important evidence when combined with filesystem and runtime indicators.",
                    confidence: "Medium",
                    detector: name
                )
            )
        } else {
            results.append(
                DetectionResult(
                    id: "iossecuritysuite.jailbreak_clear",
                    name: "No IOSSecuritySuite jailbreak indicators",
                    category: .jailbreak,
                    detected: false,
                    severity: 0,
                    explanation: "IOSSecuritySuite did not report a jailbreak or failed checks in this session.",
                    technicalDetails: "The system reported a clean jailbreak status from the library.",
                    whyItMatters: "This result is useful but not definitive because localized bypasses may hide jailbreak artifacts.",
                    confidence: "Medium",
                    detector: name
                )
            )
        }

        if IOSSecuritySuite.amIDebugged() {
            results.append(
                DetectionResult(
                    id: "iossecuritysuite.debugger",
                    name: "Debugger detected",
                    category: .debugger,
                    detected: true,
                    severity: 6,
                    explanation: "The process appears to be attached to a debugger.",
                    technicalDetails: "amIDebugged() returned true.",
                    whyItMatters: "Debugger attachment is a common runtime protection signal, but it is also possible to see it in development or forensic tooling.",
                    confidence: "High",
                    detector: name
                )
            )
        } else {
            results.append(
                DetectionResult(
                    id: "iossecuritysuite.debugger_clear",
                    name: "No debugger reported",
                    category: .debugger,
                    detected: false,
                    severity: 0,
                    explanation: "IOSSecuritySuite did not detect an attached debugger.",
                    technicalDetails: "amIDebugged() returned false.",
                    whyItMatters: "This is useful evidence but should be combined with other checks because some attackers hide or detach debugging tools.",
                    confidence: "Medium",
                    detector: name
                )
            )
        }

        if IOSSecuritySuite.amIReverseEngineered() {
            results.append(
                DetectionResult(
                    id: "iossecuritysuite.reverse_engineering",
                    name: "Reverse engineering indicators detected",
                    category: .runtime,
                    detected: true,
                    severity: 5,
                    explanation: "The library reported reverse engineering tooling or suspicious runtime indicators.",
                    technicalDetails: "amIReverseEngineered() returned true.",
                    whyItMatters: "This may indicate hooking, instrumentation, or generic reverse engineering activity.",
                    confidence: "Medium",
                    detector: name
                )
            )
        } else {
            results.append(
                DetectionResult(
                    id: "iossecuritysuite.reverse_engineering_clear",
                    name: "No reverse engineering indicators reported",
                    category: .runtime,
                    detected: false,
                    severity: 0,
                    explanation: "No reverse engineering indicators were reported during the session.",
                    technicalDetails: "amIReverseEngineered() returned false.",
                    whyItMatters: "This is a useful negative signal, not proof of cleanliness.",
                    confidence: "Medium",
                    detector: name
                )
            )
        }

        return results
        #else
        return [
            DetectionResult(
                id: "iossecuritysuite.unavailable",
                name: "IOSSecuritySuite unavailable",
                category: .integrity,
                detected: false,
                severity: 0,
                explanation: "The IOSSecuritySuite package was not linked into this build, so the detection library is unavailable.",
                technicalDetails: "The app should integrate IOSSecuritySuite through Swift Package Manager on iOS.",
                whyItMatters: "This is intentionally marked unavailable rather than silently ignored.",
                confidence: "Low",
                detector: name
            )
        ]
        #endif
    }
}
