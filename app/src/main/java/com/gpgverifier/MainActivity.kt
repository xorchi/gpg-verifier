package com.gpgverifier

import com.gpgverifier.R

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
import androidx.compose.foundation.layout.Box
import androidx.compose.material.icons.filled.Info
import androidx.compose.material.icons.filled.BugReport
import androidx.compose.material.icons.filled.MoreVert
import androidx.compose.material.icons.filled.Palette
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material.icons.filled.Description
import androidx.compose.material.icons.filled.Info
import androidx.compose.material.icons.filled.Palette
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material.icons.outlined.Description
import androidx.compose.material.icons.outlined.Info
import androidx.compose.material.icons.outlined.Palette
import androidx.compose.material.icons.outlined.Settings
import androidx.compose.material.icons.outlined.Key
import androidx.compose.material.icons.outlined.Lock
import androidx.compose.material.icons.outlined.LockOpen
import androidx.compose.material.icons.outlined.Shield
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalContext
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat
import com.gpgverifier.ui.screens.AboutScreen
import com.gpgverifier.ui.screens.AppearanceScreen
import com.gpgverifier.ui.screens.DecryptScreen
import com.gpgverifier.ui.screens.KeyringScreen
import com.gpgverifier.ui.screens.SettingsScreen
import com.gpgverifier.ui.screens.SignEncryptScreen
import com.gpgverifier.ui.screens.LogViewerScreen
import com.gpgverifier.ui.screens.TextViewerScreen
import com.gpgverifier.ui.screens.VerifyScreen
import com.gpgverifier.prefs.AppPreferences
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
    NavItem("Verify",  Icons.Filled.Shield,      Icons.Outlined.Shield),
    NavItem("Sign",    Icons.Filled.Lock,        Icons.Outlined.Lock),
    NavItem("Decrypt", Icons.Filled.LockOpen,    Icons.Outlined.LockOpen),
    NavItem("Keys",    Icons.Filled.Key,         Icons.Outlined.Key),
    NavItem("Viewer",  Icons.Filled.Description, Icons.Outlined.Description),
)

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        if (Security.getProvider("BC") == null) Security.addProvider(BouncyCastleProvider())
        AppLogger.init(filesDir)
        AppLogger.i("App started — Build ${android.os.Build.VERSION.SDK_INT} device=${android.os.Build.MODEL}")
        checkAndRequestPermissions()
        enableEdgeToEdge()
        setContent {
            val context = androidx.compose.ui.platform.LocalContext.current
            var theme  by androidx.compose.runtime.remember { androidx.compose.runtime.mutableStateOf(AppPreferences.get(applicationContext, AppPreferences.KEY_THEME, AppPreferences.DEFAULT_THEME)) }
            var accent by androidx.compose.runtime.remember { androidx.compose.runtime.mutableStateOf(AppPreferences.get(applicationContext, AppPreferences.KEY_ACCENT_COLOR, AppPreferences.DEFAULT_ACCENT_COLOR)) }
            GPGVerifierTheme(theme = theme, accent = accent) {
                MainScaffold(
                    filesDir      = filesDir,
                    onThemeChange = { theme  = it },
                    onAccentChange= { accent = it }
                )
            }
        }
    }

    private fun checkAndRequestPermissions() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            if (!Environment.isExternalStorageManager()) {
                AppLogger.i("Requesting All Files Access permission (API >= 30)")
                startActivity(Intent(Settings.ACTION_MANAGE_APP_ALL_FILES_ACCESS_PERMISSION)
                    .apply { data = Uri.parse("package:$packageName") })
            } else {
                AppLogger.i("All Files Access permission already granted")
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
            if (grantResults.isNotEmpty() && grantResults[0] == PackageManager.PERMISSION_GRANTED)
                AppLogger.i("Storage permission granted")
            else
                AppLogger.w("Storage permission denied by user")
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun MainScaffold(filesDir: File, onThemeChange: (String) -> Unit, onAccentChange: (String) -> Unit) {
    var selectedTab    by remember { mutableIntStateOf(0) }
    val snackState     = remember { SnackbarHostState() }
    val scope          = rememberCoroutineScope()
    var menuExpanded by remember { mutableStateOf(false) }
    var overlay      by remember { mutableStateOf("") } // "settings" | "appearance" | "about" | "logs" | ""

    Scaffold(
        modifier = Modifier.fillMaxSize(),
        snackbarHost = { SnackbarHost(snackState) },
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.app_name)) },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = MaterialTheme.colorScheme.surface),
                actions = {
                    Box {
                        IconButton(onClick = { menuExpanded = true }) {
                            Icon(Icons.Default.MoreVert, contentDescription = "Menu")
                        }
                        DropdownMenu(expanded = menuExpanded, onDismissRequest = { menuExpanded = false }) {
                            DropdownMenuItem(
                                text = { Text(stringResource(R.string.nav_settings)) },
                                leadingIcon = { Icon(Icons.Default.Settings, null) },
                                onClick = { overlay = "settings"; menuExpanded = false; AppLogger.d("nav: overlay=Settings", AppLogger.TAG_UI) }
                            )
                            DropdownMenuItem(
                                text = { Text("Log Viewer") },
                                leadingIcon = { Icon(Icons.Default.BugReport, null) },
                                onClick = { overlay = "logs"; menuExpanded = false; AppLogger.d("nav: overlay=Logs", AppLogger.TAG_UI) }
                            )
                            DropdownMenuItem(
                                text = { Text(stringResource(R.string.nav_appearance)) },
                                leadingIcon = { Icon(Icons.Default.Palette, null) },
                                onClick = { overlay = "appearance"; menuExpanded = false; AppLogger.d("nav: overlay=Appearance", AppLogger.TAG_UI) }
                            )
                            DropdownMenuItem(
                                text = { Text(stringResource(R.string.nav_about)) },
                                leadingIcon = { Icon(Icons.Default.Info, null) },
                                onClick = { overlay = "about"; menuExpanded = false; AppLogger.d("nav: overlay=About", AppLogger.TAG_UI) }
                            )

                        }
                    }
                }
            )
        },
        bottomBar = {
            NavigationBar {
                navItems.forEachIndexed { index, item ->
                    NavigationBarItem(
                        selected  = selectedTab == index,
                        onClick   = {
                            AppLogger.d("nav: tab=${item.label}", AppLogger.TAG_UI)
                            selectedTab = index
                            overlay        = ""
                        },
                        icon      = { Icon(if (selectedTab == index) item.selectedIcon else item.unselectedIcon,
                                         contentDescription = item.label) },
                        label     = null
                    )
                }
            }
        }
    ) { innerPadding ->
        when {
            overlay == "settings"   -> SettingsScreen(filesDir = filesDir,
                                modifier = Modifier.padding(innerPadding))
            overlay == "appearance" -> AppearanceScreen(
                                onThemeChange  = onThemeChange,
                                onAccentChange = onAccentChange,
                                modifier       = Modifier.padding(innerPadding))
            overlay == "about"      -> AboutScreen(modifier = Modifier.padding(innerPadding))
            overlay == "logs"       -> LogViewerScreen(modifier = Modifier.padding(innerPadding))
            else           -> when (selectedTab) {
                0 -> VerifyScreen(modifier     = Modifier.padding(innerPadding))
                1 -> SignEncryptScreen(modifier = Modifier.padding(innerPadding))
                2 -> DecryptScreen(modifier    = Modifier.padding(innerPadding))
                3 -> KeyringScreen(modifier    = Modifier.padding(innerPadding))
                4 -> TextViewerScreen(modifier = Modifier.padding(innerPadding))
            }
        }
    }
}
