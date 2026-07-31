import NetworkExtension
import UIKit
import Darwin

final class ViewController: UITabBarController {
    override func viewDidLoad() {
        super.viewDidLoad()

        tabBar.tintColor = AppTheme.primary
        tabBar.backgroundColor = .systemBackground
        NotificationCenter.default.addObserver(self, selector: #selector(languageDidChange), name: AppLanguageStore.didChangeNotification, object: nil)
        configureTabs(selectedIndex: selectedIndex)
    }

    deinit {
        NotificationCenter.default.removeObserver(self)
    }

    private func configureTabs(selectedIndex index: Int) {
        viewControllers = [
            makeTab(HomeViewController(), title: L10n.tr("tab.home"), image: "house", selectedImage: "house.fill"),
            makeTab(OptionsViewController(), title: L10n.tr("tab.options"), image: "slider.horizontal.3", selectedImage: "slider.horizontal.3"),
            makeTab(ProfilesViewController(), title: L10n.tr("tab.profiles"), image: "folder", selectedImage: "folder.fill"),
            makeTab(SettingsViewController(), title: L10n.tr("tab.settings"), image: "gearshape", selectedImage: "gearshape.fill")
        ]
        selectedIndex = min(index, (viewControllers?.count ?? 1) - 1)
    }

    @objc private func languageDidChange() {
        configureTabs(selectedIndex: selectedIndex)
    }

    @discardableResult
    func handleDebugURL(_ url: URL) -> Bool {
#if !DEBUG
        return false
#else
        guard url.scheme?.lowercased() == "openppp2" else {
            return false
        }

        selectedIndex = 0
        let action = (url.host?.isEmpty == false ? url.host : url.pathComponents.dropFirst().first)?
            .lowercased() ?? "connect"

        switch action {
        case "connect", "start":
            connectActiveProfile(restart: false)
            return true
        case "reconnect", "restart":
            connectActiveProfile(restart: true)
            return true
        case "disconnect", "stop":
            VPNController.shared.disconnect()
            return true
        default:
            return false
        }
#endif
    }

    private func makeTab(_ root: UIViewController, title: String, image: String, selectedImage: String) -> UIViewController {
        let nav = UINavigationController(rootViewController: root)
        nav.navigationBar.prefersLargeTitles = false
        nav.tabBarItem = UITabBarItem(
            title: title,
            image: UIImage(systemName: image),
            selectedImage: UIImage(systemName: selectedImage)
        )
        return nav
    }

    private func connectActiveProfile(restart: Bool) {
        guard let profile = ProfileStore.shared.activeProfile(),
              !profile.json.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
        else {
            return
        }

        let completion: (Result<Void, Error>) -> Void = { _ in }
        if restart {
            VPNController.shared.reconnect(profile: profile, completion: completion)
        } else {
            VPNController.shared.connect(profile: profile, completion: completion)
        }
    }
}
