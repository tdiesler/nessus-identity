package io.nessus.identity.service

import io.nessus.identity.types.AuthorizationRequest
import io.nessus.identity.types.CredentialOffer
import io.nessus.identity.types.CredentialOfferV0
import io.nessus.identity.types.TokenResponse
import io.nessus.identity.types.W3CCredentialJwt

// WalletService =======================================================================================================

const val KNOWN_ISSUER_EBSI_V3 = "https://api-conformance.ebsi.eu/conformance/v3/issuer-mock"

interface WalletService: DeprecatedWalletService {

    val authorizationSvc: WalletAuthorizationService
    val defaultClientId: String

    fun createAuthorizationContext(ctx: LoginContext? = null): AuthorizationContext

    suspend fun buildAuthorizationRequest(
        authContext: AuthorizationContext,
        clientId: String = defaultClientId,
        redirectUri: String = "urn:ietf:wg:oauth:2.0:oob"
    ): AuthorizationRequest

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

    companion object {
        fun createEbsi(): WalletServiceEbsi32 {
            return WalletServiceEbsi32()
        }
        fun createKeycloak(): WalletServiceKeycloak {
            return WalletServiceKeycloak()
        }
    }
}
