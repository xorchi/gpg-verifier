package com.gpgverifier

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.os.Environment
import android.provider.Settings
import androidx.activity.ComponentActivity
import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.security.Security
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Key
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.LockOpen
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material.icons.filled.BugReport
import androidx.compose.material.icons.outlined.Key
import androidx.compose.material.icons.outlined.Lock
import androidx.compose.material.icons.outlined.LockOpen
import androidx.compose.material.icons.outlined.Shield
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalContext
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat
import com.gpgverifier.ui.screens.DecryptScreen
import com.gpgverifier.ui.screens.KeyringScreen
import com.gpgverifier.ui.screens.SignEncryptScreen
import com.gpgverifier.ui.screens.VerifyScreen
import com.gpgverifier.ui.theme.GPGVerifierTheme
import com.gpgverifier.util.AppLogger
import kotlinx.coroutines.launch
import java.io.File

data class NavItem(
    val label: String,
    val selectedIcon: ImageVector,
    val unselectedIcon: ImageVector
)

val navItems = listOf(
    NavItem("Verify",  Icons.Filled.Shield,   Icons.Outlined.Shield),
    NavItem("Sign",    Icons.Filled.Lock,     Icons.Outlined.Lock),
    NavItem("Decrypt", Icons.Filled.LockOpen, Icons.Outlined.LockOpen),
    NavItem("Keys",    Icons.Filled.Key,      Icons.Outlined.Key)
)

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        if (Security.getProvider("BC") == null) Security.addProvider(BouncyCastleProvider())
        AppLogger.init(filesDir)
        AppLogger.log("INFO: App started - onCreate()")
        checkAndRequestPermissions()
        enableEdgeToEdge()
        setContent { GPGVerifierTheme { MainScaffold(filesDir) } }
    }

    private fun checkAndRequestPermissions() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            if (!Environment.isExternalStorageManager()) {
                AppLogger.log("INFO: Requesting All Files Access permission.")
                startActivity(Intent(Settings.ACTION_MANAGE_APP_ALL_FILES_ACCESS_PERMISSION)
                    .apply { data = Uri.parse("package:$packageName") })
            } else {
                AppLogger.log("INFO: All Files Access permission has been granted")
            }
        } else {
            val perms = mutableListOf<String>()
            if (ContextCompat.checkSelfPermission(this, Manifest.permission.READ_EXTERNAL_STORAGE)
                != PackageManager.PERMISSION_GRANTED) perms.add(Manifest.permission.READ_EXTERNAL_STORAGE)
            if (ContextCompat.checkSelfPermission(this, Manifest.permission.WRITE_EXTERNAL_STORAGE)
                != PackageManager.PERMISSION_GRANTED) perms.add(Manifest.permission.WRITE_EXTERNAL_STORAGE)
            if (perms.isNotEmpty()) ActivityCompat.requestPermissions(this, perms.toTypedArray(), 100)
        }
    }

    override fun onRequestPermissionsResult(requestCode: Int, permissions: Array<String>, grantResults: IntArray) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults)
        if (requestCode == 100) {
            AppLogger.log(if (grantResults.isNotEmpty() && grantResults[0] == PackageManager.PERMISSION_GRANTED)
                "INFO: Izin storage diberikan." else "WARN: Izin storage ditolak.")
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun MainScaffold(filesDir: File) {
    var selectedTab by remember { mutableIntStateOf(0) }
    val snackState  = remember { SnackbarHostState() }
    val scope       = rememberCoroutineScope()

    Scaffold(
        modifier = Modifier.fillMaxSize(),
        snackbarHost = { SnackbarHost(snackState) },
        topBar = {
            TopAppBar(
                title = { Text("GPG Verifier") },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = MaterialTheme.colorScheme.surface),
                actions = {
                    // Tombol export log ke /sdcard/Download/
                    IconButton(onClick = {
                        scope.launch {
                            try {
                                val src = File(filesDir, "logs/app.log")
                                val dst = File("/sdcard/Download/gpgverifier-app.log")
                                if (src.exists()) {
                                    src.copyTo(dst, overwrite = true)
                                    AppLogger.log("INFO: Log diekspor ke ${dst.absolutePath}")
                                    snackState.showSnackbar("✓ Log diekspor ke Download/gpgverifier-app.log")
                                } else {
                                    snackState.showSnackbar("✗ File log belum ada")
                                }
                            } catch (e: Exception) {
                                AppLogger.log("ERROR: Export log gagal: ${e.message}")
                                snackState.showSnackbar("✗ Export log gagal: ${e.message}")
                            }
                        }
                    }) {
                        Icon(Icons.Default.BugReport, contentDescription = "Export Log")
                    }
                }
            )
        },
        bottomBar = {
            NavigationBar {
                navItems.forEachIndexed { index, item ->
                    NavigationBarItem(
                        selected  = selectedTab == index,
                        onClick   = { selectedTab = index },
                        icon      = { Icon(if (selectedTab == index) item.selectedIcon else item.unselectedIcon,
                                         contentDescription = item.label) },
                        label     = { Text(item.label) }
                    )
                }
            }
        }
    ) { innerPadding ->
        when (selectedTab) {
            0 -> VerifyScreen(modifier     = Modifier.padding(innerPadding))
            1 -> SignEncryptScreen(modifier = Modifier.padding(innerPadding))
            2 -> DecryptScreen(modifier    = Modifier.padding(innerPadding))
            3 -> KeyringScreen(modifier    = Modifier.padding(innerPadding))
        }
    }
}
