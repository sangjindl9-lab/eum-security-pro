package com.eum.security.scan

import org.junit.Assert.assertEquals
import org.junit.Test

class ThreatAssessmentTest {
    @Test fun knownHashTakesPrecedence() {
        assertEquals(ThreatVerdict.KNOWN_THREAT, ThreatAssessment.classify(true, true, true))
    }
    @Test fun noMatchIsNotSafeVerdict() {
        assertEquals(ThreatVerdict.NO_KNOWN_MATCH, ThreatAssessment.classify(false, false, true))
    }
    @Test fun incompleteScanIsNotClean() {
        assertEquals(ThreatVerdict.UNABLE_TO_SCAN, ThreatAssessment.classify(false, false, false))
    }
}
