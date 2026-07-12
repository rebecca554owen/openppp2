import XCTest
@testable import OpenPPP2Logic

@MainActor
final class RuntimeStoreTests: XCTestCase {
    private func snapshot(
        generation: UInt64,
        monotonicMs: UInt64,
        phase: RuntimePhase
    ) -> RuntimeSnapshot {
        RuntimeSnapshot(
            generation: generation,
            monotonicMs: monotonicMs,
            phase: phase
        )
    }

    func testOlderGenerationCannotOverwriteCurrentState() {
        let store = RuntimeStore(initial: snapshot(
            generation: 8,
            monotonicMs: 100,
            phase: .connected
        ))

        XCTAssertFalse(store.apply(snapshot(
            generation: 7,
            monotonicMs: 200,
            phase: .idle
        )))
        XCTAssertEqual(store.state.generation, 8)
        XCTAssertEqual(store.state.phase, .connected)
    }

    func testOlderEventWithinGenerationIsIgnored() {
        let store = RuntimeStore(initial: snapshot(
            generation: 8,
            monotonicMs: 200,
            phase: .stopping
        ))

        XCTAssertFalse(store.apply(snapshot(
            generation: 8,
            monotonicMs: 150,
            phase: .connected
        )))
        XCTAssertEqual(store.state.phase, .stopping)
    }

    func testNewGenerationReplacesPriorState() {
        let store = RuntimeStore(initial: snapshot(
            generation: 8,
            monotonicMs: 200,
            phase: .failed
        ))

        XCTAssertTrue(store.apply(snapshot(
            generation: 9,
            monotonicMs: 1,
            phase: .starting
        )))
        XCTAssertEqual(store.state.generation, 9)
        XCTAssertEqual(store.state.phase, .starting)
    }
}
