package supersocksr.ppp.android

import android.content.Context
import java.io.File

object PppStateStore {
    private const val PREFS = "openppp2_vpn_state"
    private const val KEY_STATE = "state"
    private const val KEY_UPDATED_AT = "updated_at"
    private const val KEY_STATISTICS = "statistics"
    private const val STATISTICS_FILE = "openppp2-statistics.json"

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
}
