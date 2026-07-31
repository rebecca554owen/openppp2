import UIKit

final class CrashReportsViewController: UITableViewController {
    private var rows: [String] {
        [
            L10n.tr("crash.status"),
            L10n.tr("crash.storage"),
            L10n.tr("crash.uploadToOtel"),
            L10n.tr("crash.clearLocal")
        ]
    }
    private let vpn = VPNController.shared
    private var snapshots: [CrashReporter.StoreSnapshot] = []
    private var packetTunnelSnapshotAvailable = false
    private var uploading = false

    override func viewDidLoad() {
        super.viewDidLoad()
        title = L10n.tr("settings.crashReports")
        tableView.backgroundColor = .systemGroupedBackground
        tableView.register(UITableViewCell.self, forCellReuseIdentifier: "Cell")
        reloadReports()
    }

    override func viewWillAppear(_ animated: Bool) {
        super.viewWillAppear(animated)
        reloadReports()
    }

    private func reloadReports() {
        snapshots = CrashReporter.storeSnapshots
        packetTunnelSnapshotAvailable = CrashReporter.isSharedContainerAvailable
        tableView.reloadData()
        guard !CrashReporter.isSharedContainerAvailable else { return }

        vpn.fetchPacketTunnelCrashReports { [weak self] snapshot in
            guard let self else { return }
            if let snapshot {
                self.packetTunnelSnapshotAvailable = true
                self.upsert(snapshot)
                self.tableView.reloadData()
            } else {
                self.packetTunnelSnapshotAvailable = false
                self.removeSnapshot(for: .packetTunnel)
                self.tableView.reloadData()
            }
        }
    }

    override func numberOfSections(in tableView: UITableView) -> Int {
        let packetTunnelNeedsPlaceholder = !snapshots.contains { $0.process == .packetTunnel }
        return 1 + snapshots.count + (packetTunnelNeedsPlaceholder ? 1 : 0)
    }

    override func tableView(_ tableView: UITableView, numberOfRowsInSection section: Int) -> Int {
        if section == 0 {
            return rows.count
        }
        guard let snapshot = snapshot(forSection: section) else {
            return 1
        }
        return max(snapshot.reportCount, 1)
    }

    override func tableView(_ tableView: UITableView, titleForHeaderInSection section: Int) -> String? {
        if section == 0 {
            return "KSCrash"
        }
        guard let snapshot = snapshot(forSection: section) else {
            return L10n.format("crash.pendingHeader", CrashReporter.ProcessKind.packetTunnel.localizedDisplayName)
        }
        return L10n.format("crash.pendingHeader", snapshot.process.localizedDisplayName)
    }

    override func tableView(_ tableView: UITableView, cellForRowAt indexPath: IndexPath) -> UITableViewCell {
        let cell = tableView.dequeueReusableCell(withIdentifier: "Cell", for: indexPath)
        var config = UIListContentConfiguration.valueCell()

        if indexPath.section == 0 {
            config.text = rows[indexPath.row]
            switch indexPath.row {
            case 0:
                config.secondaryText = localizedCrashReportSummary(for: snapshots)
                cell.accessoryType = .none
            case 1:
                config.secondaryText = localizedCrashStorageDescription()
                cell.accessoryType = .none
            case 2:
                config.secondaryText = uploading ? L10n.tr("crash.uploading") : L10n.tr("crash.uploadDeletesLocal")
                cell.accessoryType = uploading ? .none : .disclosureIndicator
            default:
                config.secondaryText = L10n.tr("crash.clearLocal.detail")
                cell.accessoryType = .disclosureIndicator
            }
        } else {
            guard let snapshot = snapshot(forSection: indexPath.section) else {
                config.text = L10n.tr("crash.vpnDisconnected")
                config.secondaryText = L10n.tr("crash.vpnDisconnected.detail")
                cell.accessoryType = .none
                cell.contentConfiguration = config
                return cell
            }

            if snapshot.reportIDs.isEmpty {
                config.text = L10n.tr("crash.none")
                config.secondaryText = nil
                cell.accessoryType = .none
            } else {
                let reportID = snapshot.reportIDs[indexPath.row]
                config.text = "Report \(reportID)"
                config.secondaryText = L10n.tr("crash.waitingUpload")
                cell.accessoryType = .none
            }
        }

        cell.contentConfiguration = config
        return cell
    }

    override func tableView(_ tableView: UITableView, didSelectRowAt indexPath: IndexPath) {
        tableView.deselectRow(at: indexPath, animated: true)
        guard indexPath.section == 0 else { return }

        if indexPath.row == 2 {
            uploadCrashReports()
            return
        }

        guard indexPath.row == 3 else { return }

        let alert = UIAlertController(title: L10n.tr("crash.clear.title"), message: L10n.tr("crash.clear.message"), preferredStyle: .alert)
        alert.addAction(UIAlertAction(title: L10n.tr("common.cancel"), style: .cancel))
        alert.addAction(UIAlertAction(title: L10n.tr("common.clear"), style: .destructive) { [weak self] _ in
            CrashReporter.deleteAllReports()
            guard let self else { return }
            if CrashReporter.isSharedContainerAvailable {
                self.reloadReports()
            } else {
                self.vpn.deletePacketTunnelCrashReports {
                    self.reloadReports()
                }
            }
        })
        present(alert, animated: true)
    }

    private func uploadCrashReports() {
        guard !uploading else { return }
        let settings = TelemetrySettingsStore.shared.settings()
        guard settings.canUpload, settings.includeCrashReports else {
            presentMessage(title: L10n.tr("crash.uploadDisabled.title"), message: L10n.tr("crash.uploadDisabled.message"))
            return
        }

        uploading = true
        tableView.reloadData()
        var summary = TelemetryUploadSummary()
        let group = DispatchGroup()

        group.enter()
        CrashReporter.uploadReports(for: .app, settings: settings) { result in
            summary.merge(result)
            group.leave()
        }

        if CrashReporter.isSharedContainerAvailable {
            group.enter()
            CrashReporter.uploadReports(for: .packetTunnel, settings: settings) { result in
                summary.merge(result)
                group.leave()
            }
        } else {
            group.enter()
            vpn.uploadPacketTunnelCrashReports(settings: settings) { result in
                if let result {
                    summary.merge(result)
                } else {
                    summary.skipped += 1
                    summary.lastError = L10n.tr("crash.vpnReportUnavailable")
                }
                group.leave()
            }
        }

        group.notify(queue: .main) { [weak self] in
            guard let self else { return }
            self.uploading = false
            self.reloadReports()
            let detail = summary.lastError.map { "\n\($0)" } ?? ""
            self.presentMessage(title: L10n.tr("crash.uploadFinished"), message: summary.localizedDisplayText + detail)
        }
    }

    private func snapshot(forSection section: Int) -> CrashReporter.StoreSnapshot? {
        let index = section - 1
        if snapshots.indices.contains(index) {
            return snapshots[index]
        }
        return nil
    }

    private func upsert(_ snapshot: CrashReporter.StoreSnapshot) {
        if let index = snapshots.firstIndex(where: { $0.process == snapshot.process }) {
            snapshots[index] = snapshot
        } else {
            snapshots.append(snapshot)
            snapshots.sort { $0.process.rawValue < $1.process.rawValue }
        }
    }

    private func removeSnapshot(for process: CrashReporter.ProcessKind) {
        snapshots.removeAll { $0.process == process }
    }
}
