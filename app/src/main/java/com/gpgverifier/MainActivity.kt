package com.gpgverifier

import android.Manifest
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Key
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material.icons.outlined.Key
import androidx.compose.material.icons.outlined.Shield
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat
import com.gpgverifier.ui.screens.KeyringScreen
import com.gpgverifier.ui.screens.VerifyScreen
import com.gpgverifier.ui.theme.GPGVerifierTheme
import com.gpgverifier.util.AppLogger // Import logger yang lu buat tadi

data class NavItem(
    val label: String,
    val selectedIcon: androidx.compose.ui.graphics.vector.ImageVector,
    val unselectedIcon: androidx.compose.ui.graphics.vector.ImageVector
)

val navItems = listOf(
    NavItem("Verify", Icons.Filled.Shield, Icons.Outlined.Shield),
    NavItem("Keyring", Icons.Filled.Key, Icons.Outlined.Key)
)

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        
        // Cek izin storage pas aplikasi dibuka biar bisa nulis log
        checkAndRequestPermissions()
        
        enableEdgeToEdge()
        setContent {
            GPGVerifierTheme {
                MainScaffold()
            }
        }
    }

    private fun checkAndRequestPermissions() {
        val permissions = mutableListOf<String>()
        
        // Tambahin izin baca/tulis storage ke list kalau belum di-allow
        if (ContextCompat.checkSelfPermission(this, Manifest.permission.READ_EXTERNAL_STORAGE) 
            != PackageManager.PERMISSION_GRANTED) {
            permissions.add(Manifest.permission.READ_EXTERNAL_STORAGE)
        }
        if (ContextCompat.checkSelfPermission(this, Manifest.permission.WRITE_EXTERNAL_STORAGE) 
            != PackageManager.PERMISSION_GRANTED) {
            permissions.add(Manifest.permission.WRITE_EXTERNAL_STORAGE)
        }

        if (permissions.isNotEmpty()) {
            ActivityCompat.requestPermissions(this, permissions.toTypedArray(), 100)
        } else {
            AppLogger.log("Aplikasi dibuka - Izin storage sudah ada.")
        }
    }

    // Callback pas user klik Allow/Deny di pop-up
    override fun onRequestPermissionsResult(requestCode: Int, permissions: Array<out String>, grantResults: IntArray) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults)
        if (requestCode == 100) {
            if (grantResults.isNotEmpty() && grantResults[0] == PackageManager.PERMISSION_GRANTED) {
                AppLogger.log("Izin diberikan oleh user.")
            } else {
                AppLogger.log("Izin ditolak oleh user. Logging mungkin tidak akan bekerja.")
            }
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun MainScaffold() {
    var selectedTab by remember { mutableStateOf(0) }

    Scaffold(
        modifier = Modifier.fillMaxSize(),
        topBar = {
            TopAppBar(
                title = { Text("GPG Verifier") },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = MaterialTheme.colorScheme.surface
                )
            )
        },
        bottomBar = {
            NavigationBar {
                navItems.forEachIndexed { index, item ->
                    NavigationBarItem(
                        selected = selectedTab == index,
                        onClick = { selectedTab = index },
                        icon = {
                            Icon(
                                if (selectedTab == index) item.selectedIcon else item.unselectedIcon,
                                contentDescription = item.label
                            )
                        },
                        label = { Text(item.label) }
                    )
                }
            }
        }
    ) { innerPadding ->
        when (selectedTab) {
            0 -> VerifyScreen(modifier = Modifier.padding(innerPadding))
            1 -> KeyringScreen(modifier = Modifier.padding(innerPadding))
        }
    }
}
