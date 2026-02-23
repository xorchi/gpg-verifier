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
import androidx.compose.material.icons.outlined.Key
import androidx.compose.material.icons.outlined.Lock
import androidx.compose.material.icons.outlined.LockOpen
import androidx.compose.material.icons.outlined.Shield
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat
import com.gpgverifier.ui.screens.DecryptScreen
import com.gpgverifier.ui.screens.KeyringScreen
import com.gpgverifier.ui.screens.SignEncryptScreen
import com.gpgverifier.ui.screens.VerifyScreen
import com.gpgverifier.ui.theme.GPGVerifierTheme
import com.gpgverifier.util.AppLogger

data class NavItem(
    val label: String,
    val selectedIcon: ImageVector,
    val unselectedIcon: ImageVector
)

val navItems = listOf(
    NavItem("Verify",   Icons.Filled.Shield,   Icons.Outlined.Shield),
    NavItem("Sign",     Icons.Filled.Lock,     Icons.Outlined.Lock),
    NavItem("Decrypt",  Icons.Filled.LockOpen, Icons.Outlined.LockOpen),
    NavItem("Keys",     Icons.Filled.Key,      Icons.Outlined.Key)
)

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        if (Security.getProvider("BC") == null) Security.addProvider(BouncyCastleProvider())
        AppLogger.init(filesDir) // inisialisasi logger ke storage privat
        AppLogger.log("INFO: App started - onCreate()")
        checkAndRequestPermissions()
        enableEdgeToEdge()
        setContent { GPGVerifierTheme { MainScaffold() } }
    }

    private fun checkAndRequestPermissions() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            if (!Environment.isExternalStorageManager()) {
                AppLogger.log("INFO: Meminta izin All Files Access.")
                startActivity(Intent(Settings.ACTION_MANAGE_APP_ALL_FILES_ACCESS_PERMISSION)
                    .apply { data = Uri.parse("package:$packageName") })
            } else {
                AppLogger.log("INFO: Izin All Files Access sudah diberikan.")
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
fun MainScaffold() {
    var selectedTab by remember { mutableIntStateOf(0) }
    Scaffold(
        modifier = Modifier.fillMaxSize(),
        topBar = {
            TopAppBar(
                title = { Text("GPG Verifier") },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = MaterialTheme.colorScheme.surface)
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
