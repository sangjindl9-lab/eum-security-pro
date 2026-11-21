package com.eum.security

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import androidx.lifecycle.lifecycleScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import com.eum.security.scan.ApkInspector
import com.eum.security.scan.ThreatHashStore
import com.eum.security.vpn.VpnReadiness

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val report = mutableStateOf("검사할 APK 파일을 선택하세요.")
        val picker = registerForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
            if (uri != null) {
                report.value = "검사 중..."
                lifecycleScope.launch {
                    report.value = try {
                        val result = withContext(Dispatchers.IO) {
                            ApkInspector(this@MainActivity).inspect(uri, ThreatHashStore(this@MainActivity).loadBundled().hashes)
                        }
                        "패키지: ${result.packageName ?: "분석 불가"}\n버전: ${result.versionName ?: "알 수 없음"}\nSHA-256: ${result.sha256}\n권한: ${result.permissions.joinToString()}\n서명 인증서 SHA-256: ${result.signingCertificateSha256.joinToString()}\n해시 일치: ${if (result.matchedThreat) "등록된 위협 해시와 일치" else "일치 항목 없음 (안전 판정 아님)"}\n${result.notes}"
                    } catch (e: Exception) { "검사 실패: ${e.message}" }
                }
            }
        }
        setContent {
            MaterialTheme {
                Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(24.dp), verticalArrangement = Arrangement.spacedBy(18.dp)) {
                    Text("EUM SECURITY PRO", style = MaterialTheme.typography.headlineMedium)
                    Text("개발 버전 0.3.0", style = MaterialTheme.typography.labelLarge)
                    HorizontalDivider()
                    Text("광고 차단", style = MaterialTheme.typography.titleLarge)
                    Text(if (VpnReadiness.AD_BLOCKING_AVAILABLE) "사용 가능" else "미구현 — VPN 패킷 전달 및 DNSLib 연결 필요")
                    Button(onClick = {}, enabled = VpnReadiness.AD_BLOCKING_AVAILABLE) { Text("광고 차단 시작") }
                    HorizontalDivider()
                    Text("APK SHA-256 검사", style = MaterialTheme.typography.titleLarge)
                    Button(onClick = { picker.launch(arrayOf("application/vnd.android.package-archive", "application/octet-stream", "*/*")) }) { Text("APK 파일 선택 및 해시 계산") }
                    Text(report.value)
                    HorizontalDivider()
                    Text("현재 버전은 APK 해시와 메타데이터만 분석합니다. 악성코드 판정 및 광고 차단은 제공하지 않습니다. 파일은 서버로 전송하지 않습니다.")
                }
            }
        }
    }
}
