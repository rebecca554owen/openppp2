import UIKit

@main
final class AppDelegate: UIResponder, UIApplicationDelegate {
    var window: UIWindow?

    func application(
        _ application: UIApplication,
        didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]?
    ) -> Bool {
        TelemetryIdentity.installIfNeeded()
        CrashReporter.install(process: .app)

        VPNController.shared.recoverStaleTunnelState()
        VPNController.shared.syncActiveProfileToSystemPreferences()

        let window = UIWindow(frame: UIScreen.main.bounds)
        let rootViewController = ViewController()
        window.rootViewController = rootViewController
        window.makeKeyAndVisible()
        self.window = window

        if let url = launchOptions?[.url] as? URL {
            DispatchQueue.main.async {
                _ = rootViewController.handleDebugURL(url)
            }
        }
        return true
    }

    func application(
        _ app: UIApplication,
        open url: URL,
        options: [UIApplication.OpenURLOptionsKey: Any] = [:]
    ) -> Bool {
        (window?.rootViewController as? ViewController)?.handleDebugURL(url) ?? false
    }
}
