import MobileCoreServices
import UIKit
import UniformTypeIdentifiers

final class ProfileDocumentPicker: NSObject {
    enum Event {
        case imported(ProfileExportBundle)
        case exportFinished
        case cancelled
        case failed(Error)
    }

    private weak var presenter: UIViewController?
    private var onEvent: ((Event) -> Void)?
    private var temporaryExportURL: URL?

    func presentImport(from presenter: UIViewController, onEvent: @escaping (Event) -> Void) {
        self.presenter = presenter
        self.onEvent = onEvent

        let picker: UIDocumentPickerViewController
        if #available(iOS 14.0, *) {
            picker = UIDocumentPickerViewController(forOpeningContentTypes: [.json], asCopy: true)
        } else {
            picker = UIDocumentPickerViewController(documentTypes: [kUTTypeJSON as String], in: .import)
        }
        picker.delegate = self
        picker.allowsMultipleSelection = false
        presenter.present(picker, animated: true)
    }

    func presentExport(
        data: Data,
        filename: String,
        from presenter: UIViewController,
        onEvent: @escaping (Event) -> Void
    ) {
        self.presenter = presenter
        self.onEvent = onEvent

        let directory = FileManager.default.temporaryDirectory
        let fileURL = directory.appendingPathComponent(filename)
        do {
            try data.write(to: fileURL, options: [.atomic])
            temporaryExportURL = fileURL
        } catch {
            onEvent(.failed(error))
            return
        }

        let picker = UIDocumentPickerViewController(forExporting: [fileURL], asCopy: true)
        picker.delegate = self
        presenter.present(picker, animated: true)
    }

    private func cleanupTemporaryExport() {
        if let temporaryExportURL {
            try? FileManager.default.removeItem(at: temporaryExportURL)
            self.temporaryExportURL = nil
        }
    }

    private func readImportedData(from url: URL) throws -> Data {
        let didAccess = url.startAccessingSecurityScopedResource()
        defer {
            if didAccess {
                url.stopAccessingSecurityScopedResource()
            }
        }
        return try Data(contentsOf: url)
    }
}

extension ProfileDocumentPicker: UIDocumentPickerDelegate {
    func documentPickerWasCancelled(_ controller: UIDocumentPickerViewController) {
        cleanupTemporaryExport()
        onEvent?(.cancelled)
        onEvent = nil
    }

    func documentPicker(_ controller: UIDocumentPickerViewController, didPickDocumentsAt urls: [URL]) {
        if temporaryExportURL != nil {
            cleanupTemporaryExport()
            onEvent?(.exportFinished)
            onEvent = nil
            return
        }

        guard let url = urls.first else {
            onEvent?(.failed(ProfileImportExportError.invalidFormat))
            onEvent = nil
            return
        }

        do {
            let data = try readImportedData(from: url)
            let bundle = try ProfileImportExportCodec.decode(data)
            onEvent?(.imported(bundle))
        } catch {
            onEvent?(.failed(error))
        }
        onEvent = nil
    }
}

extension UIViewController {
    static var profileSecretsWarning: String { L10n.tr("importExport.secretsWarning") }

    func confirmProfileSecretsWarning(title: String, destructive: Bool = false, onConfirm: @escaping () -> Void) {
        let alert = UIAlertController(
            title: title,
            message: Self.profileSecretsWarning,
            preferredStyle: .alert
        )
        alert.addAction(UIAlertAction(title: L10n.tr("common.cancel"), style: .cancel))
        let confirmStyle: UIAlertAction.Style = destructive ? .destructive : .default
        alert.addAction(UIAlertAction(title: L10n.tr("importExport.continue"), style: confirmStyle) { _ in
            onConfirm()
        })
        present(alert, animated: true)
    }

    func presentProfileImportModeChoice(
        profileCount: Int,
        onMerge: @escaping () -> Void,
        onReplace: @escaping () -> Void
    ) {
        let alert = UIAlertController(
            title: L10n.tr("importExport.importTitle"),
            message: L10n.format("importExport.importMessage", profileCount),
            preferredStyle: .actionSheet
        )
        alert.addAction(UIAlertAction(title: L10n.tr("importExport.merge"), style: .default) { _ in
            self.confirmProfileSecretsWarning(title: L10n.tr("importExport.confirmMerge")) {
                onMerge()
            }
        })
        alert.addAction(UIAlertAction(title: L10n.tr("importExport.replace"), style: .destructive) { _ in
            self.confirmProfileSecretsWarning(title: L10n.tr("importExport.confirmReplace"), destructive: true) {
                onReplace()
            }
        })
        alert.addAction(UIAlertAction(title: L10n.tr("common.cancel"), style: .cancel))
        if let popover = alert.popoverPresentationController {
            popover.barButtonItem = navigationItem.rightBarButtonItem
        }
        present(alert, animated: true)
    }

    func presentProfileImportResult(_ result: ProfileImportResult) {
        if result.importedCount == 0 {
            presentToast(L10n.tr("importExport.noneImported"))
            return
        }
        if result.updatedCount > 0 || result.addedCount > 0 {
            presentToast(L10n.format("importExport.addedUpdated", result.addedCount, result.updatedCount))
        } else {
            presentToast(L10n.format("importExport.imported", result.importedCount))
        }
    }
}
