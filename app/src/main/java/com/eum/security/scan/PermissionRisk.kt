package com.eum.security.scan

data class PermissionFinding(val title: String, val evidence: List<String>)

object PermissionRisk {
    private const val SMS = "android.permission.READ_SMS"
    private const val RECEIVE_SMS = "android.permission.RECEIVE_SMS"
    private const val CONTACTS = "android.permission.READ_CONTACTS"
    private const val OVERLAY = "android.permission.SYSTEM_ALERT_WINDOW"
    private const val INSTALL = "android.permission.REQUEST_INSTALL_PACKAGES"

    fun assess(permissions: Collection<String>): List<PermissionFinding> {
        val set = permissions.toSet()
        return buildList {
            if (SMS in set && CONTACTS in set) add(PermissionFinding("SMS and contacts access", listOf(SMS, CONTACTS)))
            if (RECEIVE_SMS in set && OVERLAY in set) add(PermissionFinding("SMS receiver and overlay", listOf(RECEIVE_SMS, OVERLAY)))
            if (INSTALL in set && OVERLAY in set) add(PermissionFinding("App installation and overlay", listOf(INSTALL, OVERLAY)))
        }
    }
}
