import Combine
import Foundation

@MainActor
public final class RuntimeStore: ObservableObject {
    @Published public private(set) var state: RuntimeSnapshot

    public init(
        initial: RuntimeSnapshot = RuntimeSnapshot(
            generation: 0,
            monotonicMs: 0,
            phase: .idle
        )
    ) {
        state = initial
    }

    @discardableResult
    public func apply(_ incoming: RuntimeSnapshot) -> Bool {
        if incoming.generation < state.generation {
            return false
        }
        if incoming.generation == state.generation,
           incoming.monotonicMs < state.monotonicMs {
            return false
        }
        state = incoming
        return true
    }
}
