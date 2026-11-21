package com.eum.security.scan

import android.content.Context
import org.json.JSONObject

class ThreatHashStore(private val context: Context) {
    data class Feed(val version: String, val hashes: Set<String>)
    fun loadBundled(): Feed {
        val raw = context.assets.open("threat_hashes.json").bufferedReader().use { it.readText() }
        val json = JSONObject(raw)
        val hashes = json.getJSONArray("hashes")
        val values = buildSet {
            for (i in 0 until hashes.length()) {
                val h = hashes.getString(i).lowercase()
                require(h.length == 64 && h.all { it in '0'..'9' || it in 'a'..'f' })
                add(h)
            }
        }
        return Feed(json.getString("version"), values)
    }
}
