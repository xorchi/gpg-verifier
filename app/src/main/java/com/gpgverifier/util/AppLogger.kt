package com.gpgverifier.util

import android.util.Log
import java.io.File
import java.io.FileOutputStream
import java.text.SimpleDateFormat
import java.util.*
import java.util.concurrent.atomic.AtomicLong

/**
 * Verbose application logger for GPG Verifier.
 *
 * Features:
 *  - Five log levels: VERBOSE, DEBUG, INFO, WARN, ERROR
 *  - Each entry includes: timestamp (ms precision), level, thread name + ID,
 *    call-site (class.method:line), session ID, and sequential log index.
 *  - Auto-rotation: primary log rotated to app.log.1 … app.log.5 (ring buffer).
 *  - In-memory ring buffer (last 500 entries) for fast in-app display.
 *  - Session marker written on init so log boundaries are always visible.
 *  - All file I/O is synchronised to prevent interleaved writes from coroutines.
 */
object AppLogger {

    // ── Logcat tags ───────────────────────────────────────────────────────────
    const val TAG         = "GPGVerifier"
    const val TAG_CRYPTO  = "GPGVerifier.Crypto"
    const val TAG_IO      = "GPGVerifier.IO"
    const val TAG_KEYRING = "GPGVerifier.Keyring"
    const val TAG_UI      = "GPGVerifier.UI"
    const val TAG_NET     = "GPGVerifier.Network"

    // ── Config ────────────────────────────────────────────────────────────────
    private const val MAX_LOG_BYTES     = 512 * 1024L
    private const val MAX_ROTATIONS     = 5
    private const val MEMORY_BUFFER_CAP = 500

    enum class Level { VERBOSE, DEBUG, INFO, WARN, ERROR }
    @Volatile var minLevel: Level = Level.DEBUG


    // ── Internal state ────────────────────────────────────────────────────────
    private val sessionId = UUID.randomUUID().toString().takeLast(8).uppercase()
    private val logIndex  = AtomicLong(0)
    private val fmt       = SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS", Locale.US)
    private val memBuffer = ArrayDeque<String>(MEMORY_BUFFER_CAP + 1)

    @Volatile private var logFile: File? = null
    private val fileLock = Any()

    // ── Init ──────────────────────────────────────────────────────────────────

    fun init(filesDir: File) {
        val dir = File(filesDir, "logs").also { it.mkdirs() }
        logFile = File(dir, "app.log")
        rotateIfNeeded()
        val banner = buildString {
            appendLine("=".repeat(72))
            appendLine("  GPG Verifier — Session $sessionId started")
            appendLine("  ${fmt.format(Date())}")
            appendLine(
                "  Android API ${android.os.Build.VERSION.SDK_INT}" +
                " | Device: ${android.os.Build.MANUFACTURER} ${android.os.Build.MODEL}"
            )
            appendLine("=".repeat(72))
        }
        writeRaw(banner)
        Log.i(TAG, "Logger initialised — session=$sessionId logFile=${logFile?.absolutePath}")
    }

    // ── Public log entry points ───────────────────────────────────────────────

    fun v(message: String, tag: String = TAG) = emit("VERBOSE", message, tag)
    fun d(message: String, tag: String = TAG) = emit("DEBUG",   message, tag)
    fun i(message: String, tag: String = TAG) = emit("INFO",    message, tag)
    fun w(message: String, tag: String = TAG) = emit("WARN",    message, tag)
    fun e(message: String, tag: String = TAG) = emit("ERROR",   message, tag)

    fun ex(context: String, ex: Throwable, tag: String = TAG) {
        val sb = StringBuilder()
        sb.appendLine("EXCEPTION in $context")
        sb.appendLine("  Type   : ${ex.javaClass.name}")
        sb.appendLine("  Message: ${ex.message}")
        ex.cause?.let { sb.appendLine("  Cause  : ${it.javaClass.name}: ${it.message}") }
        sb.append("  Stack  : ")
        sb.append(
            ex.stackTrace.take(10).joinToString(" ↳ ") {
                "${it.className.substringAfterLast('.')}.${it.methodName}:${it.lineNumber}"
            }
        )
        emit("ERROR", sb.toString(), tag)
        Log.e(tag, "[$context] ${ex.message}", ex)
    }

    /**
     * Compatibility shim for legacy call sites that prefix messages with
     * "DEBUG:", "ERROR", "WARN", "INFO:" etc.
     */
    fun log(message: String) {
        val upper = message.uppercase()
        when {
            upper.startsWith("ERROR") -> e(message.removePrefix("ERROR").removePrefix(":").trim())
            upper.startsWith("WARN")  -> w(message.removePrefix("WARN").removePrefix(":").trim())
            upper.startsWith("INFO")  -> i(message.removePrefix("INFO").removePrefix(":").trim())
            upper.startsWith("DEBUG") -> d(message.removePrefix("DEBUG").removePrefix(":").trim())
            else                      -> d(message)
        }
    }

    // ── Read / clear ──────────────────────────────────────────────────────────

    fun readLogs(): String = synchronized(fileLock) {
        logFile?.takeIf { it.exists() }?.readText() ?: "(log is empty)"
    }

    fun exportAllLogs(destDir: File): File {
        val dest = File(destDir, "gpgverifier-full.log")
        synchronized(fileLock) {
            dest.delete()
            val parent = logFile?.parentFile ?: return dest
            // Append rotated logs oldest first, then current
            for (i in MAX_ROTATIONS downTo 1) {
                val f = File(parent, "app.log.$i")
                if (f.exists()) dest.appendText(f.readText())
            }
            logFile?.takeIf { it.exists() }?.let { dest.appendText(it.readText()) }
        }
        return dest
    }

    fun readMemoryBuffer(n: Int = MEMORY_BUFFER_CAP): String = synchronized(memBuffer) {
        val buf = memBuffer.toList()
        val from = (buf.size - n).coerceAtLeast(0)
        buf.subList(from, buf.size).joinToString("\n")
    }

    fun clearLogs() {
        synchronized(fileLock) { logFile?.delete(); logFile?.createNewFile() }
        synchronized(memBuffer) { memBuffer.clear() }
        i("Log cleared by user")
    }

    // ── Core emit ─────────────────────────────────────────────────────────────

    private fun emit(level: String, message: String, tag: String) {
        val lvl = when (level) {
            "VERBOSE" -> Level.VERBOSE
            "DEBUG"   -> Level.DEBUG
            "INFO"    -> Level.INFO
            "WARN"    -> Level.WARN
            "ERROR"   -> Level.ERROR
            else      -> Level.DEBUG
        }
        if (lvl < minLevel) return
        val index  = logIndex.incrementAndGet()
        val ts     = fmt.format(Date())
        val thread = Thread.currentThread().let { "[${it.name}/${it.id}]" }
        val caller = resolveCallSite()
        val line   = "[$ts][$sessionId][#$index] $level/$tag $thread $caller: $message"

        when (level) {
            "VERBOSE" -> Log.v(tag, "[#$index] $caller: $message")
            "DEBUG"   -> Log.d(tag, "[#$index] $caller: $message")
            "INFO"    -> Log.i(tag, "[#$index] $caller: $message")
            "WARN"    -> Log.w(tag, "[#$index] $caller: $message")
            "ERROR"   -> Log.e(tag, "[#$index] $caller: $message")
        }

        synchronized(memBuffer) {
            if (memBuffer.size >= MEMORY_BUFFER_CAP) memBuffer.removeFirst()
            memBuffer.addLast(line)
        }

        writeRaw("$line\n")
    }

    private fun writeRaw(text: String) {
        synchronized(fileLock) {
            try {
                logFile?.let { file ->
                    FileOutputStream(file, true).use { it.write(text.toByteArray(Charsets.UTF_8)) }
                    rotateIfNeeded()
                }
            } catch (e: Exception) {
                Log.e(TAG, "AppLogger write failed: ${e.message}")
            }
        }
    }

    // ── Rotation ──────────────────────────────────────────────────────────────

    private fun rotateIfNeeded() {
        val file   = logFile ?: return
        if (!file.exists() || file.length() <= MAX_LOG_BYTES) return
        val parent = file.parentFile ?: return
        for (i in MAX_ROTATIONS downTo 2) {
            val older = File(parent, "app.log.${i - 1}")
            val newer = File(parent, "app.log.$i")
            if (older.exists()) { newer.delete(); older.renameTo(newer) }
        }
        File(parent, "app.log.1").also { it.delete() }
        file.renameTo(File(parent, "app.log.1"))
        Log.i(TAG, "Log rotated — archived as app.log.1")
    }

    // ── Call-site resolution ──────────────────────────────────────────────────

    private fun resolveCallSite(): String {
        val skip = setOf(
            "dalvik.system.VMStack",
            "java.lang.Thread",
            AppLogger::class.java.name,
            "${AppLogger::class.java.name}\$Companion"
        )
        val frame = Thread.currentThread().stackTrace
            .firstOrNull { it.className !in skip && !it.className.startsWith("java.lang.reflect") }
            ?: return "?"
        val simple = frame.className.substringAfterLast('.').substringAfterLast('$')
            .ifEmpty { frame.className.substringAfterLast('.') }
        return "$simple.${frame.methodName}:${frame.lineNumber}"
    }
}
