# RED manifest: p2p_replay_window_test

| test | break implementation | expected failure |
|------|------------------------|------------------|
| replay_rejects_duplicate_inside_window | return true from Accept for same seq | duplicate accepted |
| replay_rejects_seq_older_than_window | treat delta>=window as not duplicate | stale seq accepted |
