import UIKit

// MARK: - Profile Selector

final class SelectProfileViewController: UITableViewController {
    private let store = ProfileStore.shared
    private let searchController = UISearchController(searchResultsController: nil)
    private var profiles: [ConfigProfile] = []
    private var activeId: String?
    private var query = ""

    private var filteredProfiles: [ConfigProfile] {
        let trimmed = query.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return profiles }
        return profiles.filter { profile in
            profile.name.localizedCaseInsensitiveContains(trimmed)
                || profile.subtitle.localizedCaseInsensitiveContains(trimmed)
                || (profile.serverEndpoint?.localizedCaseInsensitiveContains(trimmed) ?? false)
        }
    }

    private var favoriteProfiles: [ConfigProfile] {
        filteredProfiles.filter { $0.favorite }
    }

    private var otherProfiles: [ConfigProfile] {
        filteredProfiles.filter { !$0.favorite }
    }

    override func viewDidLoad() {
        super.viewDidLoad()
        title = L10n.tr("profiles.selectTitle")
        tableView.backgroundColor = .systemGroupedBackground
        tableView.register(ProfileCell.self, forCellReuseIdentifier: ProfileCell.reuseIdentifier)
        navigationItem.leftBarButtonItem = UIBarButtonItem(barButtonSystemItem: .close, target: self, action: #selector(close))
        navigationItem.rightBarButtonItem = UIBarButtonItem(barButtonSystemItem: .add, target: self, action: #selector(addProfile))

        searchController.obscuresBackgroundDuringPresentation = false
        searchController.searchResultsUpdater = self
        searchController.searchBar.placeholder = L10n.tr("profiles.search")
        navigationItem.searchController = searchController
        navigationItem.hidesSearchBarWhenScrolling = false
        definesPresentationContext = true

        NotificationCenter.default.addObserver(self, selector: #selector(reload), name: ProfileStore.didChangeNotification, object: nil)
        reload()
    }

    deinit {
        NotificationCenter.default.removeObserver(self)
    }

    @objc private func reload() {
        profiles = store.profiles()
        activeId = store.activeProfile()?.id
        tableView.reloadData()
    }

    @objc private func close() {
        dismiss(animated: true)
    }

    @objc private func addProfile() {
        navigationController?.pushViewController(ProfileEditViewController(profile: nil), animated: true)
    }

    override func numberOfSections(in tableView: UITableView) -> Int {
        2
    }

    override func tableView(_ tableView: UITableView, titleForHeaderInSection section: Int) -> String? {
        section == 0 ? (favoriteProfiles.isEmpty ? nil : L10n.tr("profiles.favorites")) : L10n.tr("profiles.locations")
    }

    override func tableView(_ tableView: UITableView, numberOfRowsInSection section: Int) -> Int {
        section == 0 ? favoriteProfiles.count : otherProfiles.count
    }

    override func tableView(_ tableView: UITableView, cellForRowAt indexPath: IndexPath) -> UITableViewCell {
        let cell = tableView.dequeueReusableCell(withIdentifier: ProfileCell.reuseIdentifier, for: indexPath) as! ProfileCell
        let profile = profile(at: indexPath)
        cell.configure(profile: profile, isActive: profile.id == activeId, showsDisclosure: false)
        cell.applyGroupPosition(ProfilesViewController.groupPosition(row: indexPath.row, count: tableView.numberOfRows(inSection: indexPath.section)))
        cell.accessoryType = profile.id == activeId ? .checkmark : .none
        return cell
    }

    override func tableView(_ tableView: UITableView, didSelectRowAt indexPath: IndexPath) {
        tableView.deselectRow(at: indexPath, animated: true)
        let profile = profile(at: indexPath)
        store.setActive(profile.id)
        promptRestartForActiveTunnelIfNeeded(
            profile: profile,
            message: L10n.format("profiles.switched.message", profile.name),
            noRestartMessage: nil,
            completion: { [weak self] in
                self?.dismiss(animated: true)
            }
        )
    }

    override func tableView(_ tableView: UITableView, trailingSwipeActionsConfigurationForRowAt indexPath: IndexPath) -> UISwipeActionsConfiguration? {
        let profile = profile(at: indexPath)
        let favorite = UIContextualAction(style: .normal, title: profile.favorite ? L10n.tr("profiles.unfavorite") : L10n.tr("profiles.favorite")) { [weak self] _, _, done in
            self?.toggleFavorite(profile)
            done(true)
        }
        favorite.backgroundColor = .systemYellow

        let edit = UIContextualAction(style: .normal, title: L10n.tr("common.edit")) { [weak self] _, _, done in
            self?.navigationController?.pushViewController(ProfileEditViewController(profile: profile), animated: true)
            done(true)
        }
        edit.backgroundColor = AppTheme.primary
        return UISwipeActionsConfiguration(actions: [edit, favorite])
    }

    private func profile(at indexPath: IndexPath) -> ConfigProfile {
        indexPath.section == 0 ? favoriteProfiles[indexPath.row] : otherProfiles[indexPath.row]
    }

    private func toggleFavorite(_ profile: ConfigProfile) {
        var updated = profile
        updated.favorite.toggle()
        store.update(updated, snapshot: false)
    }
}

extension SelectProfileViewController: UISearchResultsUpdating {
    func updateSearchResults(for searchController: UISearchController) {
        query = searchController.searchBar.text ?? ""
        tableView.reloadData()
    }
}
