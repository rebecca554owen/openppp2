import UIKit

final class TelemetrySettingsViewController: UIViewController {
    private let store = TelemetrySettingsStore.shared
    private let profileStore = ProfileStore.shared
    private let vpn = VPNController.shared
    private let scrollView = UIScrollView()
    private let content = UIStackView()
    private let uploadSwitch = UISwitch()
    private let destinationControl = UISegmentedControl(items: TelemetrySettings.Destination.allCases.map(\.localizedDisplayName))
    private let endpointField = FormTextField(label: "OTLP HTTP Endpoint")
    private let crashSwitch = UISwitch()
    private let nativeSwitch = UISwitch()
    private let metricsSwitch = UISwitch()
    private let spansSwitch = UISwitch()
    private let levelControl = UISegmentedControl(items: ["Info", "Verb", "Debug", "Trace"])
    private let machineShortLabel = UILabel()
    private let machineFullLabel = UILabel()
    private let machineDeviceLabel = UILabel()
    private let developerEndpointLabel = UILabel()
    private let extensionNoteLabel = UILabel()
    private let uploadButton = UIButton(type: .system)
    private var settings = TelemetrySettings()
    private var uploading = false

    override func viewDidLoad() {
        super.viewDidLoad()
        title = L10n.tr("settings.telemetry")
        view.backgroundColor = .systemGroupedBackground
        navigationItem.rightBarButtonItem = UIBarButtonItem(
            barButtonSystemItem: .save,
            target: self,
            action: #selector(save)
        )
        setupLayout()
        load()
    }

    private func setupLayout() {
        scrollView.translatesAutoresizingMaskIntoConstraints = false
        content.axis = .vertical
        content.spacing = 12
        content.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(scrollView)
        scrollView.addSubview(content)

        NSLayoutConstraint.activate([
            scrollView.leadingAnchor.constraint(equalTo: view.leadingAnchor),
            scrollView.trailingAnchor.constraint(equalTo: view.trailingAnchor),
            scrollView.topAnchor.constraint(equalTo: view.safeAreaLayoutGuide.topAnchor),
            scrollView.bottomAnchor.constraint(equalTo: view.bottomAnchor),
            content.leadingAnchor.constraint(equalTo: scrollView.contentLayoutGuide.leadingAnchor, constant: 16),
            content.trailingAnchor.constraint(equalTo: scrollView.contentLayoutGuide.trailingAnchor, constant: -16),
            content.topAnchor.constraint(equalTo: scrollView.contentLayoutGuide.topAnchor, constant: 16),
            content.bottomAnchor.constraint(equalTo: scrollView.contentLayoutGuide.bottomAnchor, constant: -24),
            content.widthAnchor.constraint(equalTo: scrollView.frameLayoutGuide.widthAnchor, constant: -32)
        ])

        developerEndpointLabel.font = .preferredFont(forTextStyle: .footnote)
        developerEndpointLabel.textColor = .secondaryLabel
        developerEndpointLabel.numberOfLines = 0

        extensionNoteLabel.font = .preferredFont(forTextStyle: .footnote)
        extensionNoteLabel.textColor = .secondaryLabel
        extensionNoteLabel.numberOfLines = 0
        extensionNoteLabel.text = L10n.tr("telemetry.extensionNote")

        destinationControl.addTarget(self, action: #selector(destinationChanged), for: .valueChanged)
        [uploadSwitch, crashSwitch, nativeSwitch, metricsSwitch, spansSwitch].forEach {
            $0.addTarget(self, action: #selector(controlChanged), for: .valueChanged)
        }
        levelControl.addTarget(self, action: #selector(controlChanged), for: .valueChanged)

        [machineShortLabel, machineFullLabel, machineDeviceLabel].forEach {
            $0.font = .monospacedSystemFont(ofSize: 12, weight: .regular)
            $0.textColor = .secondaryLabel
            $0.numberOfLines = 0
            $0.lineBreakMode = .byCharWrapping
        }

        let copyMachineButton = UIButton(type: .system)
        copyMachineButton.setImage(UIImage(systemName: "doc.on.doc"), for: .normal)
        copyMachineButton.setTitle(L10n.tr("telemetry.copyMachineId"), for: .normal)
        copyMachineButton.titleLabel?.font = .systemFont(ofSize: 15, weight: .semibold)
        copyMachineButton.addTarget(self, action: #selector(copyMachineId), for: .touchUpInside)
        copyMachineButton.contentHorizontalAlignment = .leading

        content.addArrangedSubview(SectionView(title: L10n.tr("telemetry.identity"), symbol: "number", views: [
            machineShortLabel,
            machineFullLabel,
            machineDeviceLabel,
            copyMachineButton
        ]))

        content.addArrangedSubview(SectionView(title: L10n.tr("telemetry.upload"), symbol: "arrow.up.doc", views: [
            switchRow(title: L10n.tr("telemetry.enableUpload"), subtitle: "OTLP/HTTP JSON", control: uploadSwitch),
            destinationControl,
            developerEndpointLabel,
            endpointField
        ]))

        content.addArrangedSubview(SectionView(title: L10n.tr("telemetry.data"), symbol: "checklist", views: [
            switchRow(title: "KSCrash", subtitle: L10n.tr("telemetry.crash.detail"), control: crashSwitch),
            switchRow(title: "Native Telemetry", subtitle: L10n.tr("telemetry.native.detail"), control: nativeSwitch)
        ]))

        content.addArrangedSubview(SectionView(title: "Native", symbol: "waveform.path.ecg", views: [
            levelControl,
            switchRow(title: "Metrics", subtitle: "Counter / Gauge / Histogram", control: metricsSwitch),
            switchRow(title: "Spans", subtitle: "Trace spans", control: spansSwitch),
            extensionNoteLabel
        ]))

        uploadButton.setTitle(L10n.tr("telemetry.uploadCrashReports"), for: .normal)
        uploadButton.titleLabel?.font = .systemFont(ofSize: 17, weight: .semibold)
        uploadButton.backgroundColor = AppTheme.primary
        uploadButton.tintColor = .white
        uploadButton.layer.cornerRadius = 12
        uploadButton.addTarget(self, action: #selector(uploadCrashReports), for: .touchUpInside)
        uploadButton.heightAnchor.constraint(equalToConstant: 48).isActive = true
        content.addArrangedSubview(uploadButton)
    }

    private func load() {
        settings = store.settings()
        uploadSwitch.isOn = settings.uploadEnabled
        destinationControl.selectedSegmentIndex = TelemetrySettings.Destination.allCases.firstIndex(of: settings.destination) ?? 0
        endpointField.text = settings.customEndpoint
        crashSwitch.isOn = settings.includeCrashReports
        nativeSwitch.isOn = settings.includeNativeTelemetry
        metricsSwitch.isOn = settings.nativeMetricsEnabled
        spansSwitch.isOn = settings.nativeSpansEnabled
        levelControl.selectedSegmentIndex = max(0, min(settings.nativeLogLevel, 3))
        refreshIdentity()
        refreshControls()
    }

    private func refreshIdentity() {
        let id = TelemetryIdentity.machineId
        machineShortLabel.text = L10n.format("telemetry.shortId", String(id.prefix(12)))
        machineFullLabel.text = "machine.id: \(id)"
        let attrs = TelemetryIdentity.nativeResourceAttributes
        let model = attrs["device.model"] ?? "unknown"
        let osName = attrs["os.name"] ?? "iOS"
        let osVersion = attrs["os.version"] ?? ""
        machineDeviceLabel.text = "device: \(model) / \(osName) \(osVersion)"
    }

    private func applyForm() -> TelemetrySettings {
        var next = settings
        next.uploadEnabled = uploadSwitch.isOn
        let destinations = TelemetrySettings.Destination.allCases
        let selected = max(0, min(destinationControl.selectedSegmentIndex, destinations.count - 1))
        next.destination = destinations[selected]
        next.customEndpoint = endpointField.textValue
        next.includeCrashReports = crashSwitch.isOn
        next.includeNativeTelemetry = nativeSwitch.isOn
        next.nativeMetricsEnabled = metricsSwitch.isOn
        next.nativeSpansEnabled = spansSwitch.isOn
        next.nativeLogLevel = max(0, min(levelControl.selectedSegmentIndex, 3))
        return next
    }

    private func refreshControls() {
        let next = applyForm()
        let usesCustom = next.destination == .custom
        endpointField.isHidden = !usesCustom
        endpointField.field.isEnabled = usesCustom
        developerEndpointLabel.isHidden = usesCustom
        developerEndpointLabel.text = TelemetrySettings.developerEndpoint.isEmpty
            ? L10n.tr("telemetry.developerEndpointMissing")
            : TelemetrySettings.developerEndpoint
        let nativeControlsEnabled = next.canUpload && next.includeNativeTelemetry
        metricsSwitch.isEnabled = false
        spansSwitch.isEnabled = nativeControlsEnabled
        levelControl.isEnabled = nativeControlsEnabled
        metricsSwitch.alpha = 0.45
        spansSwitch.alpha = nativeControlsEnabled ? 1 : 0.45
        levelControl.alpha = nativeControlsEnabled ? 1 : 0.45
        uploadButton.isEnabled = next.canUpload && next.includeCrashReports && !uploading
        uploadButton.alpha = uploadButton.isEnabled ? 1 : 0.45
        uploadButton.setTitle(uploading ? L10n.tr("telemetry.uploading") : L10n.tr("telemetry.uploadCrashReports"), for: .normal)
    }

    @objc private func destinationChanged() {
        refreshControls()
    }

    @objc private func controlChanged() {
        refreshControls()
    }

    @objc private func copyMachineId() {
        UIPasteboard.general.string = TelemetryIdentity.machineId
        presentToast(L10n.tr("telemetry.machineCopied"))
    }

    @objc private func save() {
        settings = applyForm()
        guard !settings.uploadEnabled || settings.destination != .custom || !settings.customEndpoint.isEmpty else {
            presentMessage(title: L10n.tr("telemetry.endpointEmpty.title"), message: L10n.tr("telemetry.endpointEmpty.message"))
            return
        }

        if settings.uploadEnabled,
           !settings.effectiveEndpoint.isEmpty,
           URLComponents(string: settings.effectiveEndpoint)?.host == nil {
            presentMessage(title: L10n.tr("telemetry.endpointInvalid.title"), message: L10n.tr("telemetry.endpointInvalid.message"))
            return
        }

        store.save(settings)
        refreshControls()

        guard let profile = profileStore.activeProfile(), vpn.requiresRestartToApplyConfiguration else {
            presentToast(L10n.tr("telemetry.saved"))
            return
        }

        promptRestartForActiveTunnelIfNeeded(
            profile: profile,
            message: L10n.tr("telemetry.restartMessage"),
            noRestartMessage: L10n.tr("telemetry.saved")
        )
    }

    @objc private func uploadCrashReports() {
        settings = applyForm()
        guard settings.canUpload, settings.includeCrashReports else {
            presentMessage(title: L10n.tr("telemetry.cannotUpload.title"), message: L10n.tr("telemetry.cannotUpload.message"))
            return
        }

        store.save(settings)
        uploading = true
        refreshControls()
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
                    summary.lastError = L10n.tr("telemetry.vpnUploadUnavailable")
                }
                group.leave()
            }
        }

        group.notify(queue: .main) { [weak self] in
            guard let self else { return }
            self.uploading = false
            self.refreshControls()
            let detail = summary.lastError.map { "\n\($0)" } ?? ""
            self.presentMessage(title: L10n.tr("crash.uploadFinished"), message: summary.localizedDisplayText + detail)
        }
    }
}
