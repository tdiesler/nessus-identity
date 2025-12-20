package io.nessus.identity.service

import io.nessus.identity.LoginContext
import io.nessus.identity.LoginCredentials
import io.nessus.identity.types.AuthorizationRequest
import io.nessus.identity.types.AuthorizationRequestV0
import io.nessus.identity.types.CredentialOffer
import io.nessus.identity.types.TokenResponse
import io.nessus.identity.types.W3CCredentialJwt

// NativeWalletService =================================================================================================

class NoopWalletService : AbstractWalletService() {

    override val endpointUri get() = error("Not implemented")
    override val authorizationSvc get() = error("Not implemented")
    override val defaultClientId get() = error("Not implemented")

    override suspend fun authorizeWithCredentialOffer(
        ctx: LoginContext,
        clientId: String,
        credOffer: CredentialOffer,
        loginCredentials: LoginCredentials?
    ): TokenResponse {
        error("Not implemented")
    }

    override suspend fun authorizeWithCredentialOfferTokenFlow(
        ctx: LoginContext,
        credOffer: CredentialOffer
    ): String {
        error("Not implemented")
    }

    override suspend fun authorizeWithCredentialOfferCodeFlow(
        ctx: LoginContext,
        clientId: String,
        credOffer: CredentialOffer,
        loginCredentials: LoginCredentials?
    ): String {
        error("Not implemented")
    }

    override suspend fun authorizeWithCodeFlow(
        ctx: LoginContext,
        credentialIssuer: String,
        clientId: String,
        configId: String,
        redirectUri: String,
        loginCredentials: LoginCredentials?
    ): String {
        error("Not implemented")
    }

    override suspend fun authorizeWithDirectAccess(
        ctx: LoginContext,
        credentialIssuer: String,
        clientId: String,
        configId: String,
        loginCredentials: LoginCredentials
    ): TokenResponse {
        error("Not implemented")
    }

    override suspend fun buildAuthorizationRequestForCodeFlow(
        ctx: LoginContext,
        clientId: String,
        scopes: List<String>,
        redirectUri: String
    ): AuthorizationRequest {
        error("Not implemented")
    }

    override suspend fun buildAuthorizationRequestForIDTokenFlow(
        ctx: LoginContext,
        credOffer: CredentialOffer
    ): AuthorizationRequest {
        error("Not implemented")
    }

    override suspend fun getAccessTokenFromCode(
        ctx: LoginContext,
        authCode: String
    ): TokenResponse {
        error("Not implemented")
    }

    override suspend fun getCredentialOfferFromUri(offerUri: String): CredentialOffer {
        error("Not implemented")
    }

    override suspend fun getCredential(
        ctx: LoginContext,
        accessToken: TokenResponse
    ): W3CCredentialJwt {
        error("Not implemented")
    }

    override suspend fun getCredentialFromOffer(
        ctx: LoginContext,
        credOffer: CredentialOffer,
        loginCredentials: LoginCredentials?
    ): W3CCredentialJwt {
        error("Not implemented")
    }

    override suspend fun handleVPTokenRequest(
        ctx: LoginContext,
        authReq: AuthorizationRequestV0
    ): TokenResponse {
        error("Not implemented")
    }

}