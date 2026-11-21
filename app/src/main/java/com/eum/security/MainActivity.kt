package com.eum.security

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.*
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent { SecurityHome() }
    }
}
@Composable
fun SecurityHome() {
    MaterialTheme {
        Column(Modifier.fillMaxSize().padding(24.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
            Text("EUM SECURITY PRO", style = MaterialTheme.typography.headlineMedium)
            Text("Development build — security protection is not active.")
            Text("VPN filtering: not implemented")
            Text("Production malware signatures: not configured")
            Text("APK static inspection: pending integration")
        }
    }
}
