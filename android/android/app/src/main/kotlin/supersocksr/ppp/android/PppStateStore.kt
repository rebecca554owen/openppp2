package supersocksr.ppp.android

import android.content.Context
import java.io.File

object PppStateStore {
    private const val PREFS = "openppp2_vpn_state"
    private const val KEY_STATE = "state"
    private const val KEY_UPDATED_AT = "updated_at"
    private const val KEY_STATISTICS = "statistics"
    private const val STATISTICS_FILE = "openppp2-statistics.json"
    private const val LINK_STATE_FILE = "openppp2-linkstate.txt"
    private const val RUNTIME_SNAPSHOT_FILE = "openppp2-runtime-snapshot.json"
    private const val LAST_ERROR_FILE = "openppp2-lasterror.txt"

    /** Heartbeat older than this means the `:vpn` process is gone. */
    const val HEARTBEAT_STALE_MS = 30_000L

    /**
     * Writes through a temporary file and renames it into place. A plain
     * writeText() truncates first, so a reader in the other process can
     * observe an empty or half-written file; rename(2) is atomic.
     */
    private fun writeAtomically(context: Context, name: String, text: String) {
        var temp: File? = null
        try {
            // A unique temp per call: the poller thread and the stop path can
            // both publish the same file, and a shared temp would let them
            // interleave into a corrupt payload before the rename.
            temp = File.createTempFile("$name.", ".tmp", context.filesDir)
            temp.writeText(text)
            if (!temp.renameTo(File(context.filesDir, name))) {
                temp.delete()
            }
        } catch (_: Throwable) {
            // best-effort cross-process pipe; fall through silently
            temp?.delete()
        }
    }

    fun set(context: Context, state: Int) {
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .edit()
            .putInt(KEY_STATE, state)
            .putLong(KEY_UPDATED_AT, System.currentTimeMillis())
            .apply()
    }

    fun get(context: Context): Int {
        return context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .getInt(KEY_STATE, 0)
    }

    fun updatedAt(context: Context): Long {
        return context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .getLong(KEY_UPDATED_AT, 0L)
    }

    fun setStatistics(context: Context, json: String) {
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .edit()
            .putString(KEY_STATISTICS, json)
            .apply()
        writeAtomically(context, STATISTICS_FILE, json)
    }

    fun getStatistics(context: Context): String {
        val file = File(context.filesDir, STATISTICS_FILE)
        if (file.exists()) {
            val text = file.readText()
            if (text.isNotBlank()) return text
        }
        return context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .getString(KEY_STATISTICS, "{}") ?: "{}"
    }

    /**
     * Cross-process link state. The native libopenppp2 state lives in the
     * `:vpn` process; the UI/Flutter process cannot call get_link_state()
     * directly because each process has its own copy of the loaded library.
     * Instead, [PppVpnService] polls the native value and writes it here, which
     * doubles as the liveness heartbeat; [MainActivity] reads it back for the
     * UI process.
     *
     * Values mirror the native enum in libopenppp2.cpp:
     *   0 ESTABLISHED, 1 UNKNOWN, 2 CLIENT_UNINITIALIZED,
     *   3 EXCHANGE_UNINITIALIZED, 4 RECONNECTING, 5 CONNECTING,
     *   6 APPLICATION_UNINITIALIZED.
     */
    fun setLinkState(context: Context, value: Int) {
        writeAtomically(context, LINK_STATE_FILE, value.toString())
    }

    fun getLinkState(context: Context): Int {
        return try {
            val f = File(context.filesDir, LINK_STATE_FILE)
            if (!f.exists()) return 6
            f.readText().trim().toIntOrNull() ?: 6
        } catch (_: Throwable) {
            6
        }
    }

    fun clearLinkState(context: Context) {
        try {
            File(context.filesDir, LINK_STATE_FILE).delete()
        } catch (_: Throwable) {
        }
    }

    /**
     * Milliseconds since [PppVpnService] last rewrote the link-state file, or
     * -1 when no session has written one. The poller rewrites it every second
     * while the tunnel is alive, so a stale age means `:vpn` died.
     */
    fun heartbeatAgeMs(context: Context): Long {
        return try {
            val f = File(context.filesDir, LINK_STATE_FILE)
            if (!f.exists()) -1L else System.currentTimeMillis() - f.lastModified()
        } catch (_: Throwable) {
            -1L
        }
    }

    fun isVpnAlive(context: Context): Boolean {
        return heartbeatAgeMs(context) in 0..HEARTBEAT_STALE_MS
    }

    /**
     * Runtime snapshot JSON produced by the native engine. The engine runs in
     * `:vpn`, so the UI process cannot read it directly; the service mirrors
     * every published snapshot here and the UI reads it back.
     */
    fun setRuntimeSnapshot(context: Context, json: String) {
        writeAtomically(context, RUNTIME_SNAPSHOT_FILE, json)
    }

    /**
     * Returns the mirrored snapshot only while `:vpn` is alive. A snapshot left
     * behind by a dead session must not be presented as current state.
     */
    fun getRuntimeSnapshotIfAlive(context: Context): String? {
        if (!isVpnAlive(context)) {
            return null
        }
        return try {
            val f = File(context.filesDir, RUNTIME_SNAPSHOT_FILE)
            if (!f.exists()) null else f.readText().ifBlank { null }
        } catch (_: Throwable) {
            null
        }
    }

    fun clearRuntimeSnapshot(context: Context) {
        try {
            File(context.filesDir, RUNTIME_SNAPSHOT_FILE).delete()
        } catch (_: Throwable) {
        }
    }

    /**
     * Last failure reported by the service. Errors raised in `:vpn` before or
     * around the native call never reach the runtime snapshot, so they are
     * mirrored separately.
     */
    fun setLastError(context: Context, message: String) {
        writeAtomically(context, LAST_ERROR_FILE, message)
    }

    fun getLastError(context: Context): String {
        return try {
            val f = File(context.filesDir, LAST_ERROR_FILE)
            if (!f.exists()) "" else f.readText()
        } catch (_: Throwable) {
            ""
        }
    }

    fun clearLastError(context: Context) {
        try {
            File(context.filesDir, LAST_ERROR_FILE).delete()
        } catch (_: Throwable) {
        }
    }
}
