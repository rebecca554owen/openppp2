package supersocksr.ppp.android

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.system.OsConstants
import android.util.Log
import org.json.JSONObject
import supersocksr.ppp.android.c.libopenppp2

class PppVpnService : VpnService() {
    companion object {
        private const val TAG = "PppVpnService"
        private const val CHANNEL_ID = "openppp2_vpn_channel"
        private const val NOTIFICATION_ID = 1

        const val ACTION_CONNECT = "supersocksr.ppp.android.ACTION_CONNECT"
        const val ACTION_DISCONNECT = "supersocksr.ppp.android.ACTION_DISCONNECT"
        const val EXTRA_CONFIG = "config_json"
        const val EXTRA_VPN_OPTIONS = "vpn_options_json"

        var instance: PppVpnService? = null
            private set

        var isRunning = false
            private set

        var currentState = 0
            private set
    }

    private var vpnInterface: ParcelFileDescriptor? = null
    private var vpnThread: Thread? = null

    override fun onCreate() {
        super.onCreate()
        instance = this
        createNotificationChannel()
        PppLog.write(this, "PppVpnService created")
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        try {
            PppLog.write(this, "onStartCommand action=${intent?.action}")
            when (intent?.action) {
                ACTION_CONNECT -> {
                    val config = intent.getStringExtra(EXTRA_CONFIG) ?: return START_NOT_STICKY
                    val vpnOptions = intent.getStringExtra(EXTRA_VPN_OPTIONS) ?: "{}"
                    startVpn(config, vpnOptions)
                }
                ACTION_DISCONNECT -> {
                    stopVpn()
                }
            }
        } catch (e: Throwable) {
            PppLog.write(this, "onStartCommand failed", e)
            notifyError("onStartCommand failed: ${e.message ?: e.javaClass.name}")
            notifyStateChanged(0)
            stopSelf()
        }
        return START_STICKY
    }

    override fun onDestroy() {
        stopVpn()
        isRunning = false
        currentState = 0
        PppStateStore.set(this, 0)
        vpnInterface?.close()
        vpnInterface = null
        instance = null
        super.onDestroy()
    }

    override fun onRevoke() {
        stopVpn()
        super.onRevoke()
    }

    private fun startVpn(configJson: String, vpnOptionsJson: String) {
        if (isRunning) {
            Log.w(TAG, "VPN is already running")
            return
        }

        startForeground(NOTIFICATION_ID, buildNotification("正在连接..."))
        PppLog.write(this, "startForeground done")
        notifyStateChanged(1) // connecting

        try {
            // Set app configuration
            val options = JSONObject(vpnOptionsJson)
            val vpnIp = options.optString("tunIp", "10.0.0.2")
            val vpnMask = options.optString("tunMask", "255.255.255.0")
            val vpnPrefix = options.optInt("tunPrefix", 24)
            val route = options.optString("route", "0.0.0.0")
            val routePrefix = options.optInt("routePrefix", 0)
            val dns1 = options.optString("dns1", "8.8.8.8")
            val dns2 = options.optString("dns2", "8.8.4.4")
            val mtu = options.optInt("mtu", 1400)
            val mark = options.optInt("mark", 0)
            val mux = options.optInt("mux", 0)
            val vnet = options.optBoolean("vnet", false)
            val blockQuic = options.optBoolean("blockQuic", false)
            val staticMode = options.optBoolean("staticMode", false)
            val bypassIpList = options.optString("bypassIpList", "")
            val dnsRulesList = options.optString("dnsRulesList", "")
            PppLog.write(
                this,
                "vpn options tunIp=$vpnIp tunMask=$vpnMask tunPrefix=$vpnPrefix route=$route/$routePrefix dns1=$dns1 dns2=$dns2 mtu=$mtu mark=$mark mux=$mux vnet=$vnet blockQuic=$blockQuic staticMode=$staticMode bypassIpList=${bypassIpList.isNotBlank()} dnsRulesList=${dnsRulesList.isNotBlank()}"
            )

            val configResult = libopenppp2.set_app_configuration(configJson)
            PppLog.write(this, "set_app_configuration result=$configResult")
            if (configResult != 0) {
                notifyError("set_app_configuration failed: $configResult, error: ${libopenppp2.get_last_error_text()}")
                notifyStateChanged(0) // disconnected
                stopForeground(true)
                stopSelf()
                return
            }

            // Set bypass IP list and DNS rules if provided
            if (bypassIpList.isNotBlank()) {
                val bypassResult = libopenppp2.set_bypass_ip_list(bypassIpList)
                PppLog.write(this, "set_bypass_ip_list result=$bypassResult")
            }
            if (dnsRulesList.isNotBlank()) {
                val dnsResult = libopenppp2.set_dns_rules_list(dnsRulesList)
                PppLog.write(this, "set_dns_rules_list result=$dnsResult")
            }

            val builder = Builder()
                .setSession("OpenPPP2")
                .addAddress(vpnIp, vpnPrefix)
                .addRoute(route, routePrefix)
                .allowFamily(OsConstants.AF_INET)
                .setMtu(mtu)
                .setBlocking(true)

            if (dns1.isNotBlank()) {
                builder.addDnsServer(dns1)
            }
            if (dns2.isNotBlank()) {
                builder.addDnsServer(dns2)
            }
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP && mark != 0) {
                builder.setConfigureIntent(buildConfigureIntent())
            }

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                builder.setMetered(false)
            }

            vpnInterface = builder.establish()
            PppLog.write(this, "builder.establish result=${vpnInterface != null}")
            if (vpnInterface == null) {
                notifyError("Failed to establish VPN interface")
                notifyStateChanged(0) // disconnected
                stopForeground(true)
                stopSelf()
                return
            }

            // detachFd() transfers ownership of the file descriptor to native code.
            // Using .fd directly causes fdsan SIGABRT when native close() runs because
            // ParcelFileDescriptor still claims ownership.
            val tunFd = vpnInterface!!.detachFd()
            vpnInterface = null
            PppLog.write(this, "detached tun fd=$tunFd")

            // Set network interface for native layer
            val niResult = libopenppp2.set_network_interface(
                tunFd,
                mux,
                vnet,
                blockQuic,
                staticMode,
                vpnIp,
                vpnMask
            )
            PppLog.write(this, "set_network_interface result=$niResult")
            if (niResult != 0) {
                notifyError("set_network_interface failed: $niResult, error: ${libopenppp2.get_last_error_text()}")
                vpnInterface?.close()
                vpnInterface = null
                notifyStateChanged(0)
                stopForeground(true)
                stopSelf()
                return
            }

            // Start VPN in background thread (run() is blocking)
            PppLog.write(this, "before libopenppp2.run(0)")
            isRunning = true
            vpnThread = Thread({
                try {
                    PppLog.write(this, "vpnThread started, calling run(0)")
                    val result = libopenppp2.run(0)
                    PppLog.write(this, "libopenppp2.run returned=$result")
                    if (result != 0) {
                        PppLog.write(this, "libopenppp2 last error=${libopenppp2.get_last_error_text()}")
                    }
                    Log.i(TAG, "libopenppp2.run() returned: $result")
                } catch (e: Throwable) {
                    Log.e(TAG, "VPN thread exception", e)
                    PppLog.write(this, "VPN thread exception", e)
                    notifyError("VPN thread exception: ${e.message ?: e.javaClass.name}")
                } finally {
                    isRunning = false
                    vpnInterface?.close()
                    vpnInterface = null
                    notifyStateChanged(0) // disconnected
                    stopForeground(true)
                    stopSelf()
                }
            }, "openppp2-vpn-thread").also { it.start() }

        } catch (e: Throwable) {
            Log.e(TAG, "startVpn exception", e)
            PppLog.write(this, "startVpn exception", e)
            notifyError("startVpn exception: ${e.message ?: e.javaClass.name}")
            notifyStateChanged(0)
            stopForeground(true)
            stopSelf()
        }
    }

    private fun stopVpn() {
        PppLog.write(this, "stopVpn requested, isRunning=$isRunning")
        if (!isRunning) return

        notifyStateChanged(3) // disconnecting
        try {
            libopenppp2.stop()
        } catch (e: Throwable) {
            Log.e(TAG, "stop exception", e)
            PppLog.write(this, "stop exception", e)
        }
        // The vpnThread will exit after run() returns, cleaning up in finally block
    }

    fun onStarted(key: Int) {
        Log.i(TAG, "VPN started with key: $key")
        PppLog.write(this, "onStarted key=$key")
        PppLog.write(this, "VPN started with key=$key")
        notifyStateChanged(2) // connected
        updateNotification("已连接")
    }

    fun onStatistics(json: String) {
        PppLog.write(this, "statistics=$json")
        PppStateStore.setStatistics(this, json)
        MainActivity.sendEvent(mapOf("type" to "statistics", "value" to json))
    }

    private fun notifyStateChanged(state: Int) {
        currentState = state
        PppStateStore.set(this, state)
        MainActivity.sendEvent(mapOf("type" to "state", "value" to state))
    }

    private fun notifyError(message: String) {
        Log.e(TAG, message)
        PppLog.write(this, message)
        MainActivity.sendEvent(mapOf("type" to "error", "value" to message))
    }

    private fun buildConfigureIntent(): PendingIntent {
        return PendingIntent.getActivity(
            this, 1,
            Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE
        )
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                "OpenPPP2 VPN",
                NotificationManager.IMPORTANCE_LOW
            ).apply {
                description = "VPN service notification"
            }
            val manager = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
            manager.createNotificationChannel(channel)
        }
    }

    private fun buildNotification(text: String): Notification {
        val pendingIntent = PendingIntent.getActivity(
            this, 0,
            Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE
        )

        val builder = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            Notification.Builder(this, CHANNEL_ID)
        } else {
            @Suppress("DEPRECATION")
            Notification.Builder(this)
        }

        return builder
            .setContentTitle("OpenPPP2")
            .setContentText(text)
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setContentIntent(pendingIntent)
            .setOngoing(true)
            .build()
    }

    private fun updateNotification(text: String) {
        val manager = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        manager.notify(NOTIFICATION_ID, buildNotification(text))
    }
}
