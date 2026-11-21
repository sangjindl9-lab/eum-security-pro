package com.eum.security.scan

enum class ThreatVerdict { KNOWN_THREAT, CAUTION, NO_KNOWN_MATCH, UNABLE_TO_SCAN }

object ThreatAssessment {
    fun classify(hashMatch: Boolean, suspiciousPermissions: Boolean, scanCompleted: Boolean): ThreatVerdict =
        when {
            !scanCompleted -> ThreatVerdict.UNABLE_TO_SCAN
            hashMatch -> ThreatVerdict.KNOWN_THREAT
            suspiciousPermissions -> ThreatVerdict.CAUTION
            else -> ThreatVerdict.NO_KNOWN_MATCH
        }
}
