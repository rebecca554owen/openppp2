import XCTest
@testable import OpenPPP2Logic

final class AppGroupResolverTests: XCTestCase {
    // Aim: configured app-group string wins after trimming whitespace.
    func test_resolve_prefers_configured_group() {
        let value = AppGroupResolver.resolve(
            configured: " group.custom ",
            bundleIdentifier: "com.example.app"
        )
        XCTAssertEqual(value, "group.custom")
    }

    // Aim: when no config is set, derive group from bundle identifier.
    func test_resolve_falls_back_to_bundle_id() {
        let value = AppGroupResolver.resolve(
            configured: nil,
            bundleIdentifier: "com.example.openppp2"
        )
        XCTAssertEqual(value, "group.com.example.openppp2")
    }

    // Aim: blank config and missing bundle id fall back to the default group.
    func test_resolve_uses_default_when_missing_inputs() {
        let value = AppGroupResolver.resolve(configured: "  ", bundleIdentifier: nil)
        XCTAssertEqual(value, "group.openppp2")
    }

    // Aim: empty bundle id is ignored; default group is used.
    func test_resolve_rejects_empty_bundle_id() {
        let value = AppGroupResolver.resolve(configured: nil, bundleIdentifier: "")
        XCTAssertEqual(value, "group.openppp2")
    }
}
