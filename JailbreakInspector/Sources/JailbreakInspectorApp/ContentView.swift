import SwiftUI
import JailbreakInspectorCore

struct ContentView: View {
    @ObservedObject var viewModel: ScanViewModel
    @State private var selectedDetection: DetectionResult?

    var detectedFindings: [DetectionResult] {
        viewModel.scan.detections.filter(\.detected)
    }

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(alignment: .leading, spacing: 18) {
                    Text("Jailbreak Inspector")
                        .font(.largeTitle)
                        .bold()

                    Button(action: {
                        viewModel.refresh()
                    }) {
                        Text("Scan Device")
                            .frame(maxWidth: .infinity)
                    }
                    .buttonStyle(.borderedProminent)

                    VStack(alignment: .leading, spacing: 6) {
                        Text("Assessment")
                            .font(.headline)
                        Text(viewModel.scan.assessment)
                            .font(.title2)
                            .bold()
                    }

                    VStack(alignment: .leading, spacing: 6) {
                        Text("Detection score")
                            .font(.headline)
                        Text("\(viewModel.scan.score) / 20")
                            .font(.title2)
                            .bold()
                    }

                    VStack(alignment: .leading, spacing: 6) {
                        Text("Detected findings")
                            .font(.headline)
                        Text("\(detectedFindings.count)")
                            .font(.title2)
                            .bold()
                    }

                    ForEach(DetectionCategory.allCases, id: \.self) { category in
                        let matched = viewModel.scan.detections.filter { $0.category == category }
                        let positiveCount = matched.filter(\.detected).count

                        VStack(alignment: .leading, spacing: 6) {
                            Text(category.rawValue)
                                .font(.title3)
                                .bold()

                            ProgressView(value: Double(positiveCount), total: max(1.0, Double(matched.count)))
                                .progressViewStyle(.linear)
                        }

                        DisclosureGroup(category.rawValue) {
                            ForEach(matched) { detection in
                                Button(action: {
                                    selectedDetection = detection
                                }) {
                                    HStack {
                                        Text(detection.detected ? "🔴" : "🟢")
                                        Text(detection.name)
                                        Spacer()
                                        Text("sev: \(detection.severity)")
                                    }
                                }
                                .buttonStyle(.plain)
                                .padding(.vertical, 4)
                            }
                        }
                    }

                    NavigationLink {
                        TechnicalDetailsView(scan: viewModel.scan)
                    } label: {
                        Text("Technical Details")
                            .frame(maxWidth: .infinity)
                    }

                    VStack(alignment: .leading, spacing: 6) {
                        Text("Detection Limitations")
                            .font(.headline)
                        VStack(alignment: .leading, spacing: 6) {
                            Text("• Jailbreak detection is not cryptographically guaranteed.")
                            Text("• Detection can be bypassed or obfuscated.")
                            Text("• Some findings can have legitimate explanations.")
                            Text("• App Store sandbox restrictions limit what a normal app can inspect.")
                            Text("• Rootless and rootful jailbreaks leave different artifacts.")
                            Text("• Third-party libraries can appear in runtime inspection.")
                        }
                    }
                }
                .padding()
            }
            .navigationTitle("Jailbreak Inspector")
            .sheet(item: $selectedDetection) { detection in
                DetectionDetailView(detection: detection)
            }
        }
    }
}

struct DetectionDetailView: View {
    let detection: DetectionResult

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 14) {
                Text(detection.name)
                    .font(.title2)
                    .bold()
                Text("Category: \(detection.category.rawValue)")
                Text("Severity: \(detection.severity)")
                Text("Detected: \(detection.detected ? "Yes" : "No")")
                Text("Explanation: \(detection.explanation)")
                if let details = detection.technicalDetails {
                    Text("Technical details: \(details)")
                }
                Text("Why it matters: \(detection.whyItMatters)")
                Text("Confidence/limitations: \(detection.confidence)")
            }
            .padding()
        }
    }
}

struct TechnicalDetailsView: View {
    let scan: SecurityScan

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 14) {
                Text("Technical Details")
                    .font(.title)
                    .bold()

                ForEach(scan.detections) { detection in
                    VStack(alignment: .leading, spacing: 8) {
                        Text("Detector: \(detection.detector)")
                        Text("Name: \(detection.name)")
                        Text("Detected: \(detection.detected ? "true" : "false")")
                        Text("Severity: \(detection.severity)")
                        Text("Category: \(detection.category.rawValue)")
                        Text("Explanation: \(detection.explanation)")
                        if let technical = detection.technicalDetails {
                            Text("Technical details: \(technical)")
                        }
                    }
                    .padding()
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .background(Color.gray.opacity(0.08))
                    .cornerRadius(12)
                }
            }
            .padding()
        }
    }
}
