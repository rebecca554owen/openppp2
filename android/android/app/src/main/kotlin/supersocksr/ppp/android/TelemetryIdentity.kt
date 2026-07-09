package supersocksr.ppp.android

import android.content.Context
import android.content.res.Configuration
import android.os.Build
import android.provider.Settings
import java.security.MessageDigest
import java.util.UUID

/**
 * Stable machine identity aligned with iOS [TelemetryIdentity].
 *
 * Seed (joined by "|"):
 *   installNonce, androidId, Build.MODEL, deviceFamily, hardwareModel,
 *   packageName, teamIdPrefix (empty on Android)
 */
object TelemetryIdentity {
    private const val PREFS_NAME = "openppp2_telemetry_identity"
    private const val INSTALL_NONCE_KEY = "openppp2_machine_install_nonce_v1"

    fun installIfNeeded(context: Context) {
        machineId(context)
    }

    fun machineId(context: Context): String {
        val seed = listOf(
            installNonce(context),
            androidId(context),
            Build.MODEL ?: "",
            deviceFamily(context),
            hardwareModel(),
            context.packageName,
            "", // TeamIdentifierPrefix — not applicable on Android
        ).joinToString("|")
        return sha256(seed)
    }

    fun resourceAttributes(context: Context): Map<String, String> {
        val attrs = linkedMapOf(
            "machine.id" to machineId(context),
            "device.model" to hardwareModel(),
            "device.family" to deviceFamily(context),
            "os.name" to "Android",
            "os.version" to (Build.VERSION.RELEASE ?: ""),
        )
        val vendorId = androidId(context)
        if (vendorId.isNotEmpty()) {
            attrs["device.vendor_id_hash"] = sha256("vendor|$vendorId")
        }
        return attrs
    }

    fun nativeResourceAttributes(context: Context): Map<String, String> =
        resourceAttributes(context)

    fun identityPayload(context: Context): Map<String, Any?> = mapOf(
        "machineId" to machineId(context),
        "resourceAttributes" to resourceAttributes(context),
    )

    private fun androidId(context: Context): String {
        return try {
            Settings.Secure.getString(context.contentResolver, Settings.Secure.ANDROID_ID)
                ?: ""
        } catch (_: Throwable) {
            ""
        }
    }

    private fun deviceFamily(context: Context): String {
        val uiMode = context.resources.configuration.uiMode and
            Configuration.UI_MODE_TYPE_MASK
        return when (uiMode) {
            Configuration.UI_MODE_TYPE_TELEVISION -> "tv"
            else -> {
                val sw = context.resources.configuration.smallestScreenWidthDp
                if (sw >= 600) "tablet" else "phone"
            }
        }
    }

    /** Hardware codename (iOS utsname machine equivalent). */
    private fun hardwareModel(): String {
        return Build.DEVICE?.takeIf { it.isNotEmpty() }
            ?: Build.MODEL?.takeIf { it.isNotEmpty() }
            ?: "unknown"
    }

    private fun installNonce(context: Context): String {
        val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        val existing = prefs.getString(INSTALL_NONCE_KEY, null)
        if (!existing.isNullOrEmpty()) {
            return existing
        }
        val nonce = UUID.randomUUID().toString().lowercase()
        prefs.edit().putString(INSTALL_NONCE_KEY, nonce).apply()
        return nonce
    }

    private fun sha256(value: String): String {
        val digest = MessageDigest.getInstance("SHA-256")
        val bytes = digest.digest(value.toByteArray(Charsets.UTF_8))
        return bytes.joinToString("") { "%02x".format(it) }
    }
}
