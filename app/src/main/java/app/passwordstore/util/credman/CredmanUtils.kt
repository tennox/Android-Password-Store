/*
 * Copyright © 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */
package app.passwordstore.util.credman

import android.util.Base64
import java.security.MessageDigest
import app.passwordstore.util.services.UDCakeCredentialProviderService
import app.passwordstore.util.extensions.getString
import android.annotation.SuppressLint
import app.passwordstore.Application
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.graphics.drawable.Icon
import android.os.Bundle
import logcat.logcat
import androidx.compose.material3.Icon
import androidx.credentials.exceptions.GetCredentialUnsupportedException
import androidx.credentials.provider.AuthenticationAction
import androidx.credentials.provider.BeginCreateCredentialRequest
import androidx.credentials.provider.BeginCreateCredentialResponse
import androidx.credentials.provider.BeginCreatePublicKeyCredentialRequest
import androidx.credentials.provider.BeginGetCredentialRequest
import androidx.credentials.provider.BeginGetCredentialResponse
import androidx.credentials.provider.BeginGetPasswordOption
import androidx.credentials.provider.BeginGetPublicKeyCredentialOption
import androidx.credentials.provider.CallingAppInfo
import androidx.credentials.provider.CreateEntry
import androidx.credentials.provider.CredentialEntry
import androidx.credentials.provider.PublicKeyCredentialEntry
import androidx.credentials.webauthn.PublicKeyCredentialRequestOptions
import app.passwordstore.R
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import app.passwordstore.util.extensions.b64Encode
import app.passwordstore.util.extensions.b64Decode

object CredmanUtils {

    private val context: Context
      get() = Application.instance.applicationContext

    /**
     * Creates a new pending intent of type [action] for this app.
     *
     * @param extra: Additional input parameters put as extra with name [UDCakeCredentialProviderService.CREDENTIAL_DATA_EXTRA]
     */
    private fun createPendingIntent(
        action: String,
        extra: Bundle? = null
    ): PendingIntent {

        val intent = Intent(action).setPackage(context.packageName)

        if (extra != null) {
            intent.putExtra(UDCakeCredentialProviderService.CREDENTIAL_DATA_EXTRA, extra)
        }

        val requestCode = (100000..999999).random()

        return PendingIntent.getActivity(
            context, requestCode, intent,
            (PendingIntent.FLAG_MUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)
        )
    }

    fun processCreateCredentialRequest(request: BeginCreateCredentialRequest): BeginCreateCredentialResponse? {
        return when (request) {
            is BeginCreatePublicKeyCredentialRequest -> {
                handleCreatePasskeyQuery(request)
            }

            else -> {
                null
            }
        }
    }

    private fun handleCreatePasskeyQuery(
        request: BeginCreatePublicKeyCredentialRequest
    ): BeginCreateCredentialResponse {

        return BeginCreateCredentialResponse.Builder()
            .addCreateEntry(
                CreateEntry.Builder(
                   context.getString(R.string.key_create_passkey),
                   createPendingIntent(
                       UDCakeCredentialProviderService.CREATE_PASSKEY_INTENT_ACTION,
                   ),
                )
                .setDescription(
                   context.getString(R.string.app_name)
                )
                .setAutoSelectAllowed(true)
                .build()
            )
            .build()
    }

    fun appInfoToOrigin(info: CallingAppInfo): String {
        val cert = info.signingInfo.apkContentsSigners[0].toByteArray()
        val md = MessageDigest.getInstance("SHA-256")
        val certHash = md.digest(cert)

        val origin="android:apk-key-hash:${certHash.b64Encode()}"

        return origin
    }
}
