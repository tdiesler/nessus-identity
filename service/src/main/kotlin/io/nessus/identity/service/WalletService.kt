package io.nessus.identity.service

import com.nimbusds.jwt.SignedJWT
import id.walt.oid4vc.data.dif.PresentationSubmission
import id.walt.webwallet.db.models.WalletCredential
import io.nessus.identity.config.ConfigProvider.requireEbsiConfig
import io.nessus.identity.config.ConfigProvider.requireWalletConfig
import io.nessus.identity.config.FeatureProfile.EBSI_V32
import io.nessus.identity.config.Features
import io.nessus.identity.types.AuthorizationRequest
import io.nessus.identity.types.CredentialOffer
import io.nessus.identity.types.CredentialOfferV0
import io.nessus.identity.types.DCQLQuery
import io.nessus.identity.types.TokenResponse
import io.nessus.identity.types.W3CCredentialJwt

// WalletService =======================================================================================================

const val KNOWN_ISSUER_EBSI_V3 = "https://api-conformance.ebsi.eu/conformance/v3/issuer-mock"

interface WalletService {

    val defaultClientId: String

    val walletEndpointUri
        get() = when(Features.getProfile()) {
            EBSI_V32 -> "${requireEbsiConfig().baseUrl}/wallet"
            else -> requireWalletConfig().baseUrl
        }

    fun addCredentialOffer(ctx: LoginContext, credOffer: CredentialOffer): String

    fun getCredentialOffers(ctx: LoginContext): Map<String, CredentialOffer>

    fun getCredentialOffer(ctx: LoginContext, offerId: String): CredentialOffer?

    fun deleteCredentialOffer(ctx: LoginContext, offerId: String): CredentialOffer?

    fun deleteCredentialOffers(ctx: LoginContext, predicate: (CredentialOffer) -> Boolean)

    suspend fun findCredentials(ctx: LoginContext, predicate: (WalletCredential) -> Boolean): List<WalletCredential>

    suspend fun findCredential(ctx: LoginContext, predicate: (WalletCredential) -> Boolean): WalletCredential?

    suspend fun getCredentialById(ctx: LoginContext, vcId: String): W3CCredentialJwt?

    suspend fun getCredentialByType(ctx: LoginContext, ctype: String): W3CCredentialJwt?

    suspend fun deleteCredential(ctx: LoginContext, vcId: String): W3CCredentialJwt?

    suspend fun deleteCredentials(ctx: LoginContext, predicate: (WalletCredential) -> Boolean)

    suspend fun buildAuthorizationRequest(
        authContext: AuthorizationContext,
        clientId: String = defaultClientId,
        redirectUri: String = "urn:ietf:wg:oauth:2.0:oob"
    ): AuthorizationRequest

    suspend fun buildPresentationSubmission(
        ctx: LoginContext,
        dcql: DCQLQuery,
    ): SubmissionBundle

    suspend fun getAuthorizationCode(
        authContext: AuthorizationContext,
        clientId: String = defaultClientId,
        username: String,
        password: String,
        redirectUri: String = "urn:ietf:wg:oauth:2.0:oob"
    ): String

    suspend fun getAccessTokenFromAuthorizationCode(
        authContext: AuthorizationContext,
        authCode: String,
        clientId: String = defaultClientId,
    ): TokenResponse

    suspend fun getAccessTokenFromDirectAccess(
        authContext: AuthorizationContext,
        clientId: String = defaultClientId,
    ): TokenResponse

    suspend fun getAccessTokenFromCredentialOffer(
        authContext: AuthorizationContext,
        credOffer: CredentialOffer,
        clientId: String = defaultClientId,
    ): TokenResponse

    /**
     * Fetch the CredentialOffer for the given CredentialOfferUri
     */
    suspend fun getCredentialOffer(offerUri: String): CredentialOfferV0

    /**
     * Holder gets a Credential from an Issuer
     * https://hub.ebsi.eu/conformance/build-solutions/issue-to-holder-functional-flows#in-time-issuance
     */
    suspend fun getCredential(authContext: AuthorizationContext, accessToken: TokenResponse): W3CCredentialJwt

    suspend fun getCredentialFromOffer(authContext: AuthorizationContext, credOffer: CredentialOffer): W3CCredentialJwt

    companion object {
        fun create(): DefaultWalletService {
            return DefaultWalletService()
        }
    }
}

data class SubmissionBundle(
    val credentials: List<SignedJWT>,
    val submission: PresentationSubmission
)
