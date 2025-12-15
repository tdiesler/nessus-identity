package io.nessus.identity.service

import com.nimbusds.jwt.SignedJWT
import id.walt.webwallet.db.models.WalletCredential
import io.nessus.identity.AuthorizationContext
import io.nessus.identity.LoginContext
import io.nessus.identity.types.AuthorizationRequest
import io.nessus.identity.types.AuthorizationRequestDraft11
import io.nessus.identity.types.AuthorizationRequestV0
import io.nessus.identity.types.CredentialOffer
import io.nessus.identity.types.CredentialRequest
import io.nessus.identity.types.DCQLQuery
import io.nessus.identity.types.SubmissionBundle
import io.nessus.identity.types.TokenRequest
import io.nessus.identity.types.TokenResponse
import io.nessus.identity.types.W3CCredentialJwt
import io.nessus.identity.waltid.WaltIDServiceProvider.widWalletService

// NativeWalletService =================================================================================================

abstract class AbstractWalletService : WalletService {

    // ExperimentalWalletService ---------------------------------------------------------------------------------------

    override suspend fun createIDToken(
        ctx: LoginContext,
        authRequest: AuthorizationRequest
    ): SignedJWT {
        error("Not implemented")
    }

    override suspend fun authorizeFromCredentialOffer(
        ctx: LoginContext,
        credOffer: CredentialOffer,
        clientId: String,
    ): TokenResponse {
        error("Not implemented")
    }

    override suspend fun authorizeWithDirectAccess(
        ctx: LoginContext,
        clientId: String
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

    override suspend fun getCredentialFromOffer(ctx: LoginContext, credOffer: CredentialOffer): W3CCredentialJwt {
        error("Not implemented")
    }

    override suspend fun buildAuthorizationRequestFromOffer(
        ctx: LoginContext,
        credOffer: CredentialOffer
    ): AuthorizationRequestDraft11 {
        error("Not implemented")
    }

    override suspend fun buildCredentialRequest(
        ctx: LoginContext,
        authRequest: AuthorizationRequest
    ): CredentialRequest {
        error("Not implemented")
    }

    override suspend fun getTokenRequestFromAuthorizationCode(
        ctx: LoginContext,
        authCode: String
    ): TokenRequest {
        error("Not implemented")
    }

    override suspend fun getAccessTokenFromCode(
        ctx: LoginContext,
        authCode: String,
    ): TokenResponse {
        error("Not implemented")
    }

    override suspend fun sendAuthorizationRequest(
        ctx: LoginContext,
        authEndpointUri: String,
        authRequest: AuthorizationRequest,
    ): String {
        error("Not implemented")
    }

    override suspend fun sendTokenRequest(
        ctx: LoginContext,
        tokenRequest: TokenRequest
    ): TokenResponse {
        error("Not implemented")
    }

    // LegacyWalletService ---------------------------------------------------------------------------------------------

    @Deprecated("promote or remove")
    override suspend fun buildAuthorizationRequest(
        authContext: AuthorizationContext,
        clientId: String,
        redirectUri: String
    ): AuthorizationRequestV0 {
        error("Not implemented")
    }

    @Deprecated("promote or remove")
    override suspend fun buildPresentationSubmission(
        ctx: LoginContext,
        dcql: DCQLQuery
    ): SubmissionBundle {
        error("Not implemented")
    }

    @Deprecated("promote or remove")
    override suspend fun getAuthorizationCode(
        ctx: LoginContext,
        clientId: String,
        username: String,
        password: String,
        redirectUri: String
    ): String {
        error("Not implemented")
    }

    @Deprecated("promote or remove")
    override suspend fun handleVPTokenRequest(
        ctx: LoginContext,
        authReq: AuthorizationRequestV0
    ): TokenResponse {
        error("Not implemented")
    }

    // WalletCredentialsService ========================================================================================

    override fun addCredentialOffer(ctx: LoginContext, credOffer: CredentialOffer): String {
        val offerId = widWalletService.addCredentialOffer(ctx, credOffer)
        return offerId
    }

    override fun getCredentialOffers(ctx: LoginContext): Map<String, CredentialOffer> {
        return widWalletService.getCredentialOffers(ctx)
    }

    override fun getCredentialOffer(ctx: LoginContext, offerId: String): CredentialOffer? {
        return widWalletService.getCredentialOffer(ctx, offerId)
    }

    override fun deleteCredentialOffer(ctx: LoginContext, offerId: String): CredentialOffer? {
        return widWalletService.deleteCredentialOffer(ctx, offerId)
    }

    override fun deleteCredentialOffers(ctx: LoginContext, predicate: (CredentialOffer) -> Boolean) {
        getCredentialOffers(ctx)
            .filter { (_, v) -> predicate(v) }
            .forEach { (k, _) -> widWalletService.deleteCredentialOffer(ctx, k) }
    }

    override suspend fun findCredential(
        ctx: LoginContext,
        predicate: (WalletCredential) -> Boolean
    ): WalletCredential? {
        val res = widWalletService.listCredentials(ctx)
            .asSequence()
            .filter { predicate(it) }
            .firstOrNull()
        return res
    }

    override suspend fun findCredentials(
        ctx: LoginContext,
        predicate: (WalletCredential) -> Boolean
    ): List<WalletCredential> {
        val res = widWalletService.findCredentials(ctx, predicate)
        return res
    }

    override suspend fun getCredentialById(
        ctx: LoginContext,
        vcId: String
    ): W3CCredentialJwt? {
        val res = widWalletService.findCredentials(ctx) { it.id == vcId }
            .asSequence()
            .map {
                W3CCredentialJwt.fromEncoded(it.document)
            }.firstOrNull()
        return res
    }

    override suspend fun getCredentialByType(
        ctx: LoginContext,
        ctype: String
    ): W3CCredentialJwt? {
        val res = widWalletService.findCredentials(ctx) { true }
            .asSequence()
            .map {
                W3CCredentialJwt.fromEncoded(it.document)
            }
            .filter { it.types.contains(ctype) }
            .firstOrNull()
        return res
    }

    override suspend fun deleteCredential(
        ctx: LoginContext,
        vcId: String
    ): W3CCredentialJwt? {
        val res = widWalletService.deleteCredential(ctx, vcId)?.let {
            W3CCredentialJwt.fromEncoded(it.document)
        }
        return res
    }

    override suspend fun deleteCredentials(
        ctx: LoginContext,
        predicate: (WalletCredential) -> Boolean
    ) {
        widWalletService.findCredentials(ctx) { predicate(it) }
            .forEach { wc -> widWalletService.deleteCredential(ctx, wc.id) }
    }
}