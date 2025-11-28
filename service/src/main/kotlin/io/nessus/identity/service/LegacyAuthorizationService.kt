package io.nessus.identity.service

import com.nimbusds.jwt.SignedJWT

// LegacyAuthorizationService ==========================================================================================

interface LegacyAuthorizationService {

    fun buildAuthCodeRedirectUri(ctx: LoginContext, authCode: String): String

    suspend fun createIDToken(
        ctx: LoginContext,
        reqParams: Map<String, String>
    ): SignedJWT

    suspend fun sendIDToken(
        ctx: LoginContext,
        redirectUri: String,
        idTokenJwt: SignedJWT
    ): String
}