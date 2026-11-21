package com.eum.security.scan

import org.junit.Assert.*
import org.junit.Test

class PermissionRiskTest {
    @Test fun isolatedPermissionIsNotEnough() {
        assertTrue(PermissionRisk.assess(listOf("android.permission.READ_SMS")).isEmpty())
    }
    @Test fun combinationReportsEvidence() {
        val result = PermissionRisk.assess(listOf("android.permission.READ_SMS", "android.permission.READ_CONTACTS"))
        assertEquals(1, result.size)
        assertEquals(2, result.first().evidence.size)
    }
}
