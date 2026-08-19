import SwiftUI
import JailbreakInspectorCore

@main
struct JailbreakInspectorApp: App {
    @StateObject private var viewModel = ScanViewModel()

    var body: some Scene {
        WindowGroup {
            ContentView(viewModel: viewModel)
        }
    }
}

@MainActor
final class ScanViewModel: ObservableObject {
    @Published var scan: SecurityScan

    init() {
        self.scan = SecurityScanner().runScan()
    }

    func refresh() {
        self.scan = SecurityScanner().runScan()
    }
}
