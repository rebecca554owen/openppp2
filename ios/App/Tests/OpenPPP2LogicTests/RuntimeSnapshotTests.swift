import Foundation
import XCTest
@testable import OpenPPP2Logic

final class RuntimeSnapshotTests: XCTestCase {
    private func fixtureURL(_ name: String) -> URL {
        var root = URL(fileURLWithPath: #filePath)
        for _ in 0..<5 {
            root.deleteLastPathComponent()
        }
        return root
            .appendingPathComponent("tests")
            .appendingPathComponent("contracts")
            .appendingPathComponent("runtime-snapshot")
            .appendingPathComponent(name)
    }

    private func decodeFixture(_ name: String) throws -> RuntimeSnapshot {
        let data = try Data(contentsOf: fixtureURL(name))
        return try TunnelRuntimeBridge.decodeSnapshot(data)
    }

    func testAllCanonicalFixturesDecode() throws {
        let phases: [(String, RuntimePhase)] = [
            ("idle.json", .idle),
            ("connected.json", .connected),
            ("reconnecting.json", .reconnecting),
            ("failed.json", .failed),
        ]
        for (name, phase) in phases {
            XCTAssertEqual(try decodeFixture(name).phase, phase)
        }
    }

    func testConnectedFixtureDecodesEffectiveModeAndFutureFields() throws {
        let snapshot = try decodeFixture("connected.json")
        XCTAssertEqual(snapshot.generation, 7)
        XCTAssertEqual(snapshot.phase, .connected)
        XCTAssertEqual(snapshot.requestedMuxMode, "flow")
        XCTAssertEqual(snapshot.effectiveMuxMode, "flow")
    }

    func testFailedFixtureDecodesStructuredError() throws {
        let snapshot = try decodeFixture("failed.json")
        XCTAssertEqual(snapshot.phase, .failed)
        XCTAssertEqual(snapshot.lastError.code, 1001)
        XCTAssertTrue(snapshot.lastError.retryable)
        XCTAssertEqual(snapshot.lastError.userMessageKey, "connection.tunnel_open_failed")
    }

    func testUnsupportedSchemaIsRejected() throws {
        let data = try Data(contentsOf: fixtureURL("unsupported-schema.json"))
        XCTAssertThrowsError(try TunnelRuntimeBridge.decodeSnapshot(data))
    }

    func testUnsupportedSchemaStillExposesOrderingMetadata() throws {
        let data = try Data(contentsOf: fixtureURL("unsupported-schema.json"))
        let ordering = try TunnelRuntimeBridge.decodeOrdering(data)
        XCTAssertEqual(ordering.generation, 1)
        XCTAssertEqual(ordering.monotonicMs, 1)
    }

    func testUnknownPhaseIsRejected() {
        let text = """
        {"schema_version":1,"generation":1,"monotonic_ms":1,"phase":"teleporting"}
        """
        XCTAssertThrowsError(try TunnelRuntimeBridge.decodeSnapshot(text))
    }

    func testGenerationAndMonotonicTimeAreRequired() {
        let missingGeneration = """
        {"schema_version":1,"monotonic_ms":1,"phase":"idle"}
        """
        XCTAssertThrowsError(try TunnelRuntimeBridge.decodeSnapshot(missingGeneration))

        let missingMonotonicTime = """
        {"schema_version":1,"generation":1,"phase":"idle"}
        """
        XCTAssertThrowsError(try TunnelRuntimeBridge.decodeSnapshot(missingMonotonicTime))
    }
}
