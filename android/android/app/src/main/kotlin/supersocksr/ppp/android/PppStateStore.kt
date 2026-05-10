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
        File(context.filesDir, STATISTICS_FILE).writeText(json)
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
     * Instead, [PppVpnService] polls the native value and writes it here,
     * and [MainActivity] reads from here.
     *
     * Values mirror the native enum in libopenppp2.cpp:
     *   0 ESTABLISHED, 1 UNKNOWN, 2 CLIENT_UNINITIALIZED,
     *   3 EXCHANGE_UNINITIALIZED, 4 RECONNECTING, 5 CONNECTING,
     *   6 APPLICATION_UNINITIALIZED.
     */
    fun setLinkState(context: Context, value: Int) {
        try {
            File(context.filesDir, LINK_STATE_FILE).writeText(value.toString())
        } catch (_: Throwable) {
            // best-effort cross-process pipe; fall through silently
        }
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
}
