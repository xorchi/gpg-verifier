package com.gpgverifier.ui.screens

import android.content.Intent
import android.net.Uri
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

@Composable
fun AboutScreen(modifier: Modifier = Modifier) {
    val context     = LocalContext.current
    val scrollState = rememberScrollState()
    val packageInfo = remember {
        try { context.packageManager.getPackageInfo(context.packageName, 0) }
        catch (e: Exception) { null }
    }
    val versionName = packageInfo?.versionName ?: "unknown"
    val versionCode = packageInfo?.longVersionCode ?: 0L
    val buildType   = if (versionName.contains("nightly") || versionName.contains("dev")) "Development" else "Stable"

    Column(
        modifier = modifier.fillMaxSize().verticalScroll(scrollState).padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        Text(stringResource(R.string.nav_about), style = MaterialTheme.typography.titleMedium,
            color = MaterialTheme.colorScheme.onSurface)

        // App info card
        Card(modifier = Modifier.fillMaxWidth()) {
            Column(
                modifier = Modifier.padding(20.dp).fillMaxWidth(),
                horizontalAlignment = Alignment.CenterHorizontally,
                verticalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                Icon(Icons.Default.Shield, null,
                    modifier = Modifier.size(56.dp),
                    tint = MaterialTheme.colorScheme.primary)
                Text(stringResource(R.string.app_name), style = MaterialTheme.typography.titleLarge, fontWeight = FontWeight.Bold)
                Text(stringResource(R.string.app_version, versionName)), style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.primary)
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    AssistChip(onClick = {}, label = { Text(buildType, fontSize = 12.sp) })
                    AssistChip(onClick = {}, label = { Text(stringResource(R.string.build_version, versionCode.toInt()), fontSize = 12.sp) })
                    AssistChip(onClick = {}, label = { Text(stringResource(R.string.api_level, android.os.Build.VERSION.SDK_INT), fontSize = 12.sp) })
                }
            }
        }

        // GitHub
        SectionHeader("Source")
        Card(
            modifier = Modifier.fillMaxWidth(),
            onClick = {
                context.startActivity(Intent(Intent.ACTION_VIEW,
                    Uri.parse("https://github.com/xorchi/gpg-verifier")))
            }
        ) {
            Row(
                modifier = Modifier.padding(16.dp),
                horizontalArrangement = Arrangement.spacedBy(12.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                Icon(Icons.Default.Code, null, tint = MaterialTheme.colorScheme.primary)
                Column(modifier = Modifier.weight(1f)) {
                    Text(stringResource(R.string.about_github_repo), style = MaterialTheme.typography.bodyMedium,
                        fontWeight = FontWeight.Medium)
                    Text(stringResource(R.string.about_github_url),
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.primary)
                }
                Icon(Icons.Default.OpenInNew, null, modifier = Modifier.size(16.dp),
                    tint = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.5f))
            }
        }

        // Changelog
        SectionHeader("Changelog")
        Card(modifier = Modifier.fillMaxWidth()) {
            Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                ChangelogEntry("v1.0.2", "Current", listOf(
                    "Fix ClearSign canonical hash — GnuPG cross-tool compatibility",
                    "Fix secret key backup now saves to Downloads",
                    "Restore signerUserID subpacket in signature metadata",
                    "Restructure CI/CD workflows: dev artifact, master release"
                ))
                HorizontalDivider()
                ChangelogEntry("v1.0.1", null, listOf(
                    "Initial key import/export improvements",
                    "Detached signature support"
                ))
                HorizontalDivider()
                ChangelogEntry("v1.0.0", null, listOf(
                    "Initial release",
                    "ClearSign, detach, embedded sign & verify",
                    "Asymmetric and symmetric encrypt/decrypt",
                    "Key management"
                ))
            }
        }

        // Licenses
        SectionHeader("Licenses")
        Card(modifier = Modifier.fillMaxWidth()) {
            Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                LicenseRow("Bouncy Castle", "MIT License", "bouncycastle.org")
                HorizontalDivider()
                LicenseRow("Jetpack Compose", "Apache 2.0", "developer.android.com")
                HorizontalDivider()
                LicenseRow("Material3", "Apache 2.0", "material.io")
            }
        }

        // Device info
        SectionHeader("Device")
        Card(modifier = Modifier.fillMaxWidth()) {
            Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                InfoRow("Model",   "${android.os.Build.MANUFACTURER} ${android.os.Build.MODEL}")
                InfoRow("Android", "API ${android.os.Build.VERSION.SDK_INT} (${android.os.Build.VERSION.RELEASE})")
                InfoRow("Package", context.packageName)
            }
        }

        Spacer(Modifier.height(16.dp))
        Text(stringResource(R.string.about_open_source),
            style = MaterialTheme.typography.labelSmall,
            color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.4f),
            modifier = Modifier.align(Alignment.CenterHorizontally))
    }
}

@Composable
private fun ChangelogEntry(version: String, badge: String?, items: List<String>) {
    Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalAlignment = Alignment.CenterVertically) {
            Text(version, style = MaterialTheme.typography.labelLarge, fontWeight = FontWeight.Bold,
                color = MaterialTheme.colorScheme.primary)
            if (badge != null)
                Badge(containerColor = MaterialTheme.colorScheme.primary) {
                    Text(badge, fontSize = 10.sp, color = MaterialTheme.colorScheme.onPrimary)
                }
        }
        items.forEach { item ->
            Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                Text("•", color = MaterialTheme.colorScheme.primary,
                    style = MaterialTheme.typography.bodySmall)
                Text(item, style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.8f))
            }
        }
    }
}

@Composable
private fun LicenseRow(name: String, license: String, url: String) {
    Row(
        modifier = Modifier.fillMaxWidth().padding(vertical = 4.dp),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically
    ) {
        Column {
            Text(name, style = MaterialTheme.typography.bodyMedium, fontWeight = FontWeight.Medium)
            Text(url, style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.5f))
        }
        AssistChip(onClick = {}, label = { Text(license, fontSize = 11.sp) })
    }
}
