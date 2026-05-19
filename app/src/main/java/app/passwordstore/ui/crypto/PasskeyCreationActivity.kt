/*
 * Copyright © 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package app.passwordstore.ui.crypto

import java.security.SecureRandom
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.graphics.Bitmap
import android.graphics.ImageDecoder
import android.os.Build
import android.os.Bundle
import android.provider.MediaStore
import android.text.InputType
import android.view.Menu
import android.view.MenuItem
import android.view.View
import androidx.activity.result.contract.ActivityResultContracts
import androidx.activity.result.contract.ActivityResultContracts.StartActivityForResult
import androidx.core.content.edit
import androidx.core.view.isVisible
import androidx.core.widget.doAfterTextChanged
import androidx.lifecycle.lifecycleScope
import app.passwordstore.R
import app.passwordstore.crypto.PGPIdentifier
import app.passwordstore.crypto.errors.NoKeysProvidedException
import app.passwordstore.crypto.errors.UnusableKeyException
import app.passwordstore.data.passfile.PasswordEntry
import app.passwordstore.data.passfile.joinToCharArray
import app.passwordstore.data.passfile.splitToCharArrayListAt
import app.passwordstore.data.passfile.trimEnd
import app.passwordstore.data.repo.PasswordRepository
import app.passwordstore.databinding.PasskeyCreationActivityBinding
import app.passwordstore.ui.dialogs.DicewarePasswordGeneratorDialogFragment
import app.passwordstore.ui.dialogs.OtpImportDialogFragment
import app.passwordstore.ui.dialogs.PasswordGeneratorDialogFragment
import app.passwordstore.ui.folderselect.SelectFolderActivity
import app.passwordstore.ui.passwords.PasswordStore
import app.passwordstore.util.autofill.AutofillPreferences
import app.passwordstore.util.crypto.AESEncryption
import app.passwordstore.util.extensions.asLog
import app.passwordstore.util.extensions.base64
import app.passwordstore.util.extensions.commitChange
import app.passwordstore.util.extensions.enableEdgeToEdgeView
import app.passwordstore.util.extensions.getString
import app.passwordstore.util.extensions.isInsideRepository
import app.passwordstore.util.extensions.snackbar
import app.passwordstore.util.extensions.toByteArray
import app.passwordstore.util.extensions.unsafeLazy
import app.passwordstore.util.extensions.viewBinding
import app.passwordstore.util.extensions.wipe
import app.passwordstore.util.settings.DirectoryStructure
import app.passwordstore.util.settings.PreferenceKeys
import com.github.michaelbull.result.getOrThrow
import com.github.michaelbull.result.onErr
import com.github.michaelbull.result.onOk
import com.github.michaelbull.result.runCatching
import com.github.michaelbull.result.unwrapError
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import com.google.zxing.BinaryBitmap
import com.google.zxing.LuminanceSource
import com.google.zxing.RGBLuminanceSource
import com.google.zxing.common.HybridBinarizer
import com.google.zxing.integration.android.IntentIntegrator
import com.google.zxing.integration.android.IntentIntegrator.QR_CODE
import com.google.zxing.qrcode.QRCodeReader
import dagger.hilt.android.AndroidEntryPoint
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.nio.CharBuffer
import java.nio.file.Paths
import java.nio.file.Files
import java.nio.file.Path
import kotlin.io.path.isDirectory
import javax.inject.Inject
import kotlin.io.path.absolutePathString
import kotlin.io.path.createDirectories
import kotlin.io.path.exists
import kotlin.io.path.pathString
import kotlin.io.path.writeBytes
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import logcat.LogPriority.ERROR
import logcat.asLog
import logcat.logcat
import androidx.credentials.CreatePublicKeyCredentialRequest
import androidx.credentials.CreatePublicKeyCredentialResponse
import androidx.credentials.GetCredentialResponse
import androidx.credentials.GetPublicKeyCredentialOption
import androidx.credentials.PublicKeyCredential
import androidx.credentials.provider.CallingAppInfo
import androidx.credentials.provider.PendingIntentHandler
import androidx.credentials.provider.ProviderGetCredentialRequest
import androidx.credentials.webauthn.AuthenticatorAssertionResponse
import androidx.credentials.webauthn.AuthenticatorAttestationResponse
import androidx.credentials.webauthn.FidoPublicKeyCredential
import androidx.credentials.webauthn.PublicKeyCredentialCreationOptions
import androidx.credentials.webauthn.PublicKeyCredentialRequestOptions

@AndroidEntryPoint
class PasskeyCreationActivity : BasePGPActivity() {

  private val binding by viewBinding(PasskeyCreationActivityBinding::inflate)
  @Inject lateinit var passwordEntryFactory: PasswordEntry.Factory

  private val suggestedName by unsafeLazy { intent.getStringExtra(EXTRA_FILE_NAME) }
  private val suggestedEntryChars by unsafeLazy { intent.getCharArrayExtra(EXTRA_ENTRY) }

  private val editing by unsafeLazy { intent.getBooleanExtra(EXTRA_EDITING, false) }

  private val publicKeyRequest: CreatePublicKeyCredentialRequest? by unsafeLazy {
    val systemRequest = PendingIntentHandler.retrieveProviderCreateCredentialRequest(intent)

    if (systemRequest != null && systemRequest.callingRequest is CreatePublicKeyCredentialRequest)
      systemRequest.callingRequest as CreatePublicKeyCredentialRequest
    else null 
  }

  override fun onDestroy() {
    with(binding) {
    }
    super.onDestroy()
  }

  private val selectFolderAction =
    registerForActivityResult(StartActivityForResult()) { result ->
      if (result.resultCode == RESULT_OK) {
        val rpId = result.data?.getStringExtra(PasswordStore.REQUEST_ARG_PATH)?.let { oldPath ->
          Paths.get(oldPath).fileName.toString()  
        }
        val relPath = result.data?.getStringExtra(SelectFolderActivity.SELECTED_FOLDER_PATH)?.let { fullPath ->
          PasswordRepository.getRelativePath(fullPath, repoPath)
        } ?: ""
        rpId?.let {
          val path =
            if(relPath.isEmpty()) "/${rpId}"
            else if(Paths.get(relPath).endsWith(rpId)) relPath
            else Paths.get(relPath, rpId).toAbsolutePath().toString()
          binding.directory.setText(path)
        }  
      }
    }

  override fun onCreate(savedInstanceState: Bundle?) {
    super.onCreate(savedInstanceState)
    supportActionBar?.setDisplayHomeAsUpEnabled(true)
    title =
      if (editing) getString(R.string.edit_passkey) else getString(R.string.new_passkey_title)

    with(binding) {
      enableEdgeToEdgeView(root)
      setContentView(root)

      directory.inputType = InputType.TYPE_NULL
      directory.setOnClickListener {
        val intent = Intent(this@PasskeyCreationActivity, SelectFolderActivity::class.java)
        intent.putExtra(PasswordStore.REQUEST_ARG_PATH, directory.text.toString().trimEnd('/'))
        selectFolderAction.launch(intent)
      }
    }  

    publicKeyRequest?.let{ request -> // passkey creation requested
      val credentialId = ByteArray(32)
      SecureRandom().nextBytes(credentialId)

      val credIdHexShort = credentialId.toHexString(endIndex = 8)

      val publicKeyOptions: PublicKeyCredentialCreationOptions = PublicKeyCredentialCreationOptions(request.requestJson)

      val rpId = publicKeyOptions.rp.id
      val rpName = publicKeyOptions.rp.name
      val userDisplayName = publicKeyOptions.user.displayName
      val userName = publicKeyOptions.user.name
      val prefAlgo = publicKeyOptions.pubKeyCredParams[0]

      val suggestedFullPath = findSubdirectoryRecursive(repoPath, publicKeyOptions.rp.id) ?: Paths.get(repoPath, rpId).toAbsolutePath().toString()
      val relPath = PasswordRepository.getRelativePath(suggestedFullPath, repoPath)

      logcat {"++++++++++++++++++${rpId}+++++++++++++++"}
      logcat {"++++++++++++++++++${rpName}+++++++++++++++"}
      logcat {"++++++++++++++++++${userName}+++++++++++++++"}
      logcat {"++++++++++++++++++${userDisplayName}+++++++++++++++"}
      logcat {"++++++++++++++++++${prefAlgo}+++++++++++++++"}
      logcat {"++++++++++++++++++${request.origin}+++++++++++++++"}

      binding.directory.setText(relPath)
      binding.credId.setText("${credentialId.toHexString()}")
      binding.rpName.setText("${rpName}")
      binding.rpNameLayout.isVisible = rpId != rpName
      binding.username.setText("${userName}")
    }

    //with(binding) {
    //  val suggestedEntry: PasswordEntry? = suggestedEntryChars?.let { encrypted ->
    //    AESEncryption.decrypt(encrypted)?.let { decrypted ->
    //      passwordEntryFactory.create(decrypted).also { decrypted.wipe() }
    //    }
    //  }

    //  directory.inputType = InputType.TYPE_NULL
    //  val relPath = PasswordRepository.getRelativePath(fullPath, repoPath)
    //  directory.setText(if (relPath.isEmpty()) "/" else relPath)

    //  directory.setOnClickListener {
    //    val intent = Intent(this@PasskeyCreationActivity, SelectFolderActivity::class.java)
    //    intent.putExtra(PasswordStore.REQUEST_ARG_PATH, directory.text.toString().trimEnd('/'))
    //    selectFolderAction.launch(intent)
    //  }

    //  suggestedEntry?.clear()
    //}
  }

  override fun onCreateOptionsMenu(menu: Menu): Boolean {
    menuInflater.inflate(R.menu.pgp_handler_new_password, menu)
    return true
  }

  override fun onPrepareOptionsMenu(menu: Menu): Boolean {
    menu.findItem(R.id.save_and_copy_password).setVisible(false).setEnabled(false)
    return true
  }

  override fun onOptionsItemSelected(item: MenuItem): Boolean {
    when (item.itemId) {
      android.R.id.home -> {
        setResult(RESULT_CANCELED)
        onBackPressedDispatcher.onBackPressed()
      }
      R.id.save_password -> {
        requireKeysExist {
          requireEncryptionKeysExist(binding.directory.text.toString()) { ids -> encrypt(ids) }
        }
      }
      else -> return super.onOptionsItemSelected(item)
    }
    return true
  }

  /** Encrypts the entry */
  private fun encrypt(identifiers: List<PGPIdentifier>) {
  }

  private fun findSubdirectoryRecursive(rootPath: String, targetName: String): String? {
    val match = Files.walk(Paths.get(rootPath))
      .filter { it.isDirectory() && it.fileName.toString() == targetName }
      .findFirst()
      .orElse(null)
    return match?.let {match.toAbsolutePath().toString()}  
  }

  companion object {

    private const val KEY_PWGEN_TYPE_CLASSIC = "classic"
    private const val KEY_PWGEN_TYPE_DICEWARE = "diceware"
    const val PASSWORD_RESULT_REQUEST_KEY = "PASSWORD_GENERATOR"
    const val OTP_RESULT_REQUEST_KEY = "OTP_IMPORT"
    const val RESULT = "RESULT"
    const val RETURN_EXTRA_CREATED_FILE = "CREATED_FILE"
    const val RETURN_EXTRA_NAME = "NAME"
    const val RETURN_EXTRA_LONG_NAME = "LONG_NAME"
    const val RETURN_EXTRA_USERNAME = "USERNAME"
    const val RETURN_EXTRA_PASSWORD = "PASSWORD"
    const val EXTRA_FILE_NAME = "EXTRA_FILENAME"
    const val EXTRA_ENTRY = "EXTRA_ENTRY"
    const val EXTRA_GENERATE_PASSWORD = "EXTRA_GENERATE_PASSWORD"
    const val EXTRA_EDITING = "EXTRA_EDITING"
  }
}
