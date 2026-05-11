/*
 * Copyright © 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */
package app.passwordstore.util.services

import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import android.util.Base64
import app.passwordstore.BuildConfig
import android.app.PendingIntent
import android.content.Intent
import android.os.Bundle
import android.os.CancellationSignal
import android.os.OutcomeReceiver
import androidx.credentials.exceptions.ClearCredentialException
import androidx.credentials.exceptions.GetCredentialException
import androidx.credentials.exceptions.GetCredentialUnknownException
import androidx.credentials.exceptions.GetCredentialUnsupportedException
import androidx.credentials.provider.AuthenticationAction
import androidx.credentials.provider.BeginCreatePublicKeyCredentialRequest
import androidx.credentials.provider.BeginGetCredentialResponse
import androidx.credentials.provider.BeginGetPasswordOption
import androidx.credentials.provider.BeginGetPublicKeyCredentialOption
import androidx.credentials.provider.CallingAppInfo
import androidx.credentials.provider.CreateEntry
import androidx.credentials.provider.CredentialEntry
import androidx.credentials.provider.ProviderClearCredentialStateRequest
import androidx.credentials.provider.PublicKeyCredentialEntry
import androidx.credentials.webauthn.PublicKeyCredentialRequestOptions
import logcat.LogPriority.ERROR
import logcat.logcat
import androidx.credentials.provider.CredentialProviderService
import androidx.annotation.RequiresApi
import androidx.credentials.exceptions.CreateCredentialException
import androidx.credentials.exceptions.CreateCredentialUnknownException
import androidx.credentials.provider.BeginCreateCredentialRequest
import androidx.credentials.provider.BeginCreateCredentialResponse
import androidx.credentials.provider.BeginGetCredentialRequest
import java.security.KeyPair
import java.security.PrivateKey
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.SecureRandom
import java.security.Signature
import app.passwordstore.util.credman.CredmanUtils

@RequiresApi(34)
class UDCakeCredentialProviderService: CredentialProviderService() {

    override fun onBeginCreateCredentialRequest(
        request: BeginCreateCredentialRequest,
        cancellationSignal: CancellationSignal,
        callback: OutcomeReceiver<BeginCreateCredentialResponse, CreateCredentialException>
    ) {
        val response: BeginCreateCredentialResponse? = CredmanUtils.processCreateCredentialRequest(request)
        logcat {"++++++++++++++++++++ ${response} onBegin CREATE CredentialRequest ++++++++++++++++++++"}
        if (response != null) {
            callback.onResult(response)
        } else {
            callback.onError(CreateCredentialUnknownException())
        }
    }

    override fun onBeginGetCredentialRequest(
        request: BeginGetCredentialRequest,
        cancellationSignal: CancellationSignal,
        callback: OutcomeReceiver<BeginGetCredentialResponse, GetCredentialException>
    ) {
        logcat {"++++++++++++++++++++ onBegin GET CredentialRequest ++++++++++++++++++++"}
        //try {
        //    callback.onResult(OpenPasskeyAuthServiceUtils.processGetCredentialRequest(this.application, this, request))
        //} catch (_: GetCredentialException) {
        //    callback.onError(GetCredentialUnknownException())
        //}
    }

    override fun onClearCredentialStateRequest(
        request: ProviderClearCredentialStateRequest,
        cancellationSignal: CancellationSignal,
        callback: OutcomeReceiver<Void?, ClearCredentialException>
    ) {
        logcat {"Not implemented: onClearCredentialStateRequest"}
    }

    companion object {
        // These intent actions are specified for corresponding activities
        // that are to be invoked through the PendingIntent(s)
        const val GET_PASSKEY_INTENT_ACTION = "${BuildConfig.APPLICATION_ID}.action.GET_PASSKEY"
        const val CREATE_PASSKEY_INTENT_ACTION = "${BuildConfig.APPLICATION_ID}.action.CREATE_PASSKEY"
        const val CREDENTIAL_DATA_EXTRA = "${BuildConfig.APPLICATION_ID}.CREDENTIAL_DATA"
        const val UNLOCK_APP_INTENT_ACTION = "${BuildConfig.APPLICATION_ID}.action.UNLOCK_APP"
        const val CREDENTIAL_ID = "credentialId"
        const val ACCOUNT_ID = "accountId"
        const val DEVICE_ACCOUNT = "DEVICE_ACCOUNT_ID"
    }
}
