import UIKit

final class DebugSettingsViewController: UITableViewController {
    private let store = ProfileStore.shared

    private enum Item: CaseIterable {
        case debugPanel
        case packetDiagnostics
        case packetConsoleLogging
        case packetTelemetry

        var title: String {
            switch self {
            case .debugPanel: return L10n.tr("debug.item.panel")
            case .packetDiagnostics: return L10n.tr("debug.item.packetDiagnostics")
            case .packetConsoleLogging: return L10n.tr("debug.item.consoleLogging")
            case .packetTelemetry: return L10n.tr("debug.item.packetTelemetry")
            }
        }

        var subtitle: String {
            switch self {
            case .debugPanel:
                return L10n.tr("debug.item.panel.detail")
            case .packetDiagnostics:
                return L10n.tr("debug.item.packetDiagnostics.detail")
            case .packetConsoleLogging:
                return L10n.tr("debug.item.consoleLogging.detail")
            case .packetTelemetry:
                return L10n.tr("debug.item.packetTelemetry.detail")
            }
        }
    }

    private let items = Item.allCases

    override func viewDidLoad() {
        super.viewDidLoad()
        title = L10n.tr("debug.title")
        tableView.backgroundColor = .systemGroupedBackground
        tableView.register(UITableViewCell.self, forCellReuseIdentifier: "Cell")
    }

    override func numberOfSections(in tableView: UITableView) -> Int {
        2
    }

    override func tableView(_ tableView: UITableView, titleForHeaderInSection section: Int) -> String? {
        section == 0 ? L10n.tr("debug.section.ui") : "Packet Tunnel"
    }

    override func tableView(_ tableView: UITableView, numberOfRowsInSection section: Int) -> Int {
        section == 0 ? 1 : 3
    }

    override func tableView(_ tableView: UITableView, cellForRowAt indexPath: IndexPath) -> UITableViewCell {
        let cell = tableView.dequeueReusableCell(withIdentifier: "Cell", for: indexPath)
        let item = item(at: indexPath)
        var config = UIListContentConfiguration.subtitleCell()
        config.text = item.title
        config.secondaryText = item.subtitle
        cell.contentConfiguration = config
        cell.selectionStyle = .none

        let toggle = UISwitch()
        toggle.isOn = isEnabled(item)
        toggle.tag = tag(for: item)
        toggle.addTarget(self, action: #selector(toggleChanged(_:)), for: .valueChanged)
        cell.accessoryView = toggle
        return cell
    }

    override func tableView(_ tableView: UITableView, titleForFooterInSection section: Int) -> String? {
        section == 1 ? L10n.tr("debug.packetTunnel.footer") : nil
    }

    private func item(at indexPath: IndexPath) -> Item {
        indexPath.section == 0 ? .debugPanel : items[indexPath.row + 1]
    }

    private func tag(for item: Item) -> Int {
        switch item {
        case .debugPanel: return 0
        case .packetDiagnostics: return 1
        case .packetConsoleLogging: return 2
        case .packetTelemetry: return 3
        }
    }

    private func item(for tag: Int) -> Item? {
        switch tag {
        case 0: return .debugPanel
        case 1: return .packetDiagnostics
        case 2: return .packetConsoleLogging
        case 3: return .packetTelemetry
        default: return nil
        }
    }

    private func isEnabled(_ item: Item) -> Bool {
        let debug = store.debugSettings()
        switch item {
        case .debugPanel:
            return store.debugPanelEnabled()
        case .packetDiagnostics:
            return debug.packetFlowDiagnosticsEnabled
        case .packetConsoleLogging:
            return debug.packetFlowConsoleLoggingEnabled
        case .packetTelemetry:
            return debug.packetFlowTelemetryEnabled
        }
    }

    @objc private func toggleChanged(_ sender: UISwitch) {
        guard let item = item(for: sender.tag) else { return }
        switch item {
        case .debugPanel:
            store.setDebugPanelEnabled(sender.isOn)
        case .packetDiagnostics:
            store.setPacketFlowDiagnosticsEnabled(sender.isOn)
        case .packetConsoleLogging:
            store.setPacketFlowConsoleLoggingEnabled(sender.isOn)
        case .packetTelemetry:
            store.setPacketFlowTelemetryEnabled(sender.isOn)
        }
    }
}
