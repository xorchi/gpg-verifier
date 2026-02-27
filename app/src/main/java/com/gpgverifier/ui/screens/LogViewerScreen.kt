package com.gpgverifier.ui.screens

import androidx.compose.foundation.background
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.gpgverifier.R
import com.gpgverifier.util.AppLogger
import kotlinx.coroutines.launch

private data class LogLine(
    val raw: String,
    val level: String,   // DEBUG INFO WARN ERROR
    val tag: String,
    val message: String
)

private fun parseLevel(raw: String): String = when {
    raw.contains("] DEBUG/") -> "DEBUG"
    raw.contains("] INFO/")  -> "INFO"
    raw.contains("] WARN/")  -> "WARN"
    raw.contains("] ERROR/") -> "ERROR"
    else                     -> "INFO"
}

private fun parseTag(raw: String): String {
    val match = Regex("""(?:DEBUG|INFO|WARN|ERROR)/([^\s\[]+)""").find(raw)
    return match?.groupValues?.get(1)?.substringAfterLast('.') ?: ""
}

private fun levelColor(level: String): Color = when (level) {
    "DEBUG" -> Color(0xFF888888)
    "INFO"  -> Color(0xFF4CAF50)
    "WARN"  -> Color(0xFFFF9800)
    "ERROR" -> Color(0xFFEF5350)
    else    -> Color(0xFF888888)
}

@Composable
fun LogViewerScreen(modifier: Modifier = Modifier) {
    val scope = rememberLazyListState()
    val corScope = rememberCoroutineScope()
    val clipboard = LocalClipboardManager.current
    val snack = remember { SnackbarHostState() }

    var allLines by remember { mutableStateOf<List<LogLine>>(emptyList()) }
    var selectedLevels by remember { mutableStateOf(setOf("DEBUG","INFO","WARN","ERROR")) }
    var selectedTag by remember { mutableStateOf("All") }
    var autoScroll by remember { mutableStateOf(true) }

    // Load logs
    fun reload() {
        val raw = AppLogger.readLogs()
        allLines = raw.lines().filter { it.isNotBlank() }.map { line ->
            LogLine(
                raw     = line,
                level   = parseLevel(line),
                tag     = parseTag(line),
                message = line
            )
        }
    }

    LaunchedEffect(Unit) { reload() }

    val availableTags = remember(allLines) {
        listOf("All") + allLines.map { it.tag }.filter { it.isNotEmpty() }.distinct().sorted()
    }

    val filtered = remember(allLines, selectedLevels, selectedTag) {
        allLines.filter { line ->
            line.level in selectedLevels &&
            (selectedTag == "All" || line.tag == selectedTag)
        }
    }

    // Auto scroll to bottom
    LaunchedEffect(filtered.size) {
        if (autoScroll && filtered.isNotEmpty()) {
            scope.animateScrollToItem(filtered.size - 1)
        }
    }

    Scaffold(snackbarHost = { SnackbarHost(snack) }) { padding ->
        Column(modifier = modifier.padding(padding).fillMaxSize()) {

            // ── Toolbar ──────────────────────────────────────────────────────
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .background(MaterialTheme.colorScheme.surface)
                    .padding(horizontal = 12.dp, vertical = 6.dp),
                horizontalArrangement = Arrangement.spacedBy(6.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text("Log Viewer",
                    style = MaterialTheme.typography.titleSmall,
                    modifier = Modifier.weight(1f))

                // Refresh
                IconButton(onClick = { reload() }, modifier = Modifier.size(36.dp)) {
                    Icon(Icons.Default.Refresh, "Refresh", modifier = Modifier.size(18.dp))
                }

                // Copy filtered
                IconButton(
                    onClick = {
                        val text = filtered.joinToString("\n") { it.raw }
                        clipboard.setText(AnnotatedString(text))
                        corScope.launch { snack.showSnackbar("✓ ${filtered.size} lines copied") }
                    },
                    modifier = Modifier.size(36.dp)
                ) {
                    Icon(Icons.Default.ContentCopy, "Copy", modifier = Modifier.size(18.dp))
                }

                // Auto scroll toggle
                IconButton(
                    onClick = { autoScroll = !autoScroll },
                    modifier = Modifier.size(36.dp)
                ) {
                    Icon(
                        if (autoScroll) Icons.Default.VerticalAlignBottom else Icons.Default.VerticalAlignCenter,
                        "Auto scroll",
                        modifier = Modifier.size(18.dp),
                        tint = if (autoScroll) MaterialTheme.colorScheme.primary
                               else MaterialTheme.colorScheme.onSurface.copy(alpha = 0.4f)
                    )
                }
            }

            HorizontalDivider()

            // ── Level Filter ─────────────────────────────────────────────────
            Row(
                modifier = Modifier
                    .horizontalScroll(rememberScrollState())
                    .padding(horizontal = 12.dp, vertical = 4.dp),
                horizontalArrangement = Arrangement.spacedBy(6.dp)
            ) {
                listOf("DEBUG","INFO","WARN","ERROR").forEach { lvl ->
                    val selected = lvl in selectedLevels
                    FilterChip(
                        selected = selected,
                        onClick = {
                            selectedLevels = if (selected && selectedLevels.size > 1)
                                selectedLevels - lvl
                            else
                                selectedLevels + lvl
                        },
                        label = { Text(lvl, fontSize = 11.sp) },
                        colors = FilterChipDefaults.filterChipColors(
                            selectedContainerColor = levelColor(lvl).copy(alpha = 0.2f),
                            selectedLabelColor = levelColor(lvl)
                        ),
                        modifier = Modifier.height(28.dp)
                    )
                }
            }

            // ── Tag Filter ───────────────────────────────────────────────────
            if (availableTags.size > 2) {
                Row(
                    modifier = Modifier
                        .horizontalScroll(rememberScrollState())
                        .padding(horizontal = 12.dp, vertical = 2.dp),
                    horizontalArrangement = Arrangement.spacedBy(6.dp)
                ) {
                    availableTags.forEach { tag ->
                        FilterChip(
                            selected = selectedTag == tag,
                            onClick = { selectedTag = tag },
                            label = { Text(tag, fontSize = 10.sp) },
                            modifier = Modifier.height(26.dp)
                        )
                    }
                }
            }

            HorizontalDivider()

            // ── Log Lines ────────────────────────────────────────────────────
            if (filtered.isEmpty()) {
                Box(modifier = Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                    Text("No log entries", color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.4f))
                }
            } else {
                SelectionContainer {
                    LazyColumn(
                        state = scope,
                        modifier = Modifier
                            .fillMaxSize()
                            .horizontalScroll(rememberScrollState())
                            .padding(horizontal = 8.dp, vertical = 4.dp)
                    ) {
                        items(filtered) { line ->
                            Text(
                                text = line.raw,
                                fontFamily = FontFamily.Monospace,
                                fontSize = 10.sp,
                                color = levelColor(line.level),
                                lineHeight = 14.sp,
                                modifier = Modifier.padding(vertical = 1.dp)
                            )
                        }
                    }
                }
            }
        }
    }
}
