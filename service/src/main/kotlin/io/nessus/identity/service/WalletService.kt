package io.nessus.identity.service

import io.nessus.identity.LoginContext
import io.nessus.identity.LoginCredentials
import io.nessus.identity.config.ConfigProvider.requireWalletConfig
import io.nessus.identity.config.FeatureProfile.EBSI_V32
import io.nessus.identity.config.Features
import io.nessus.identity.types.AuthorizationRequest
import io.nessus.identity.types.AuthorizationRequestV0
import io.nessus.identity.types.CredentialOffer
import io.nessus.identity.types.TokenResponse
import io.nessus.identity.types.W3CCredentialJwt

interface WalletService: WalletCredentialsService {

    /**
     * The endpoint uri for this service
     */
    val endpointUri: String

    /**
     * The AuthorizationService for this service
     */
    val authorizationSvc: AuthorizationService

    // [TODO] Get default client_id from config
    val defaultClientId: String

    companion object {
        fun createNative(): WalletService {
            val config = if(Features.isProfile(EBSI_V32)) {
                requireWalletConfig("proxy")
            } else {
                requireWalletConfig("native")
            }
            return NativeWalletService(config)
        }
    }

    /**
     * Authorize the Wallet from a CredentialOffer
     */
    suspend fun authorizeWithCredentialOffer(
        ctx: LoginContext,
        clientId: String,
        credOffer: CredentialOffer,
        loginCredentials: LoginCredentials? = null
    ): TokenResponse

    /**
     * Authorize the Wallet from a CredentialOffer with IDToken Flow
     */
    suspend fun authorizeWithCredentialOfferTokenFlow(
        ctx: LoginContext,
        credOffer: CredentialOffer
    ): String

    /**
     * Authorize the Wallet from a CredentialOffer with Code Flow
     */
    suspend fun authorizeWithCredentialOfferCodeFlow(
        ctx: LoginContext,
        clientId: String,
        credOffer: CredentialOffer,
        loginCredentials: LoginCredentials? = null
    ): String

    /**
     * Authorize the Wallet using OIDC Code Flow
     */
    suspend fun authorizeWithCodeFlow(
        ctx: LoginContext,
        credentialIssuer: String,
        clientId: String,
        configId: String,
        redirectUri: String = "urn:ietf:wg:oauth:2.0:oob",
        loginCredentials: LoginCredentials? = null
    ): String

    /**
     * Authorize the Wallet using OIDC Direct Access (not recommended)
     */
    suspend fun authorizeWithDirectAccess(
        ctx: LoginContext,
        credentialIssuer: String,
        clientId: String,
        configId: String,
        loginCredentials: LoginCredentials
    ): TokenResponse

    suspend fun buildAuthorizationRequestForCodeFlow(
        ctx: LoginContext,
        clientId: String,
        scopes: List<String>,
        redirectUri: String = "urn:ietf:wg:oauth:2.0:oob"
    ): AuthorizationRequest

    suspend fun buildAuthorizationRequestForIDTokenFlow(
        ctx: LoginContext,
        credOffer: CredentialOffer
    ): AuthorizationRequest

    /**
     * Get an access Token
     */
    suspend fun getAccessTokenFromCode(
        ctx: LoginContext,
        authCode: String,
    ): TokenResponse

    /**
     * The Wallet fetches a Credential for the given AccessToken
     */
    suspend fun getCredential(
        ctx: LoginContext,
        accessToken: TokenResponse
    ): W3CCredentialJwt

    /**
     * The Wallet gets the Credential for the given CredentialOffer
     *
     * This is a high-level entry method that involves the necessary authorization steps.
     * The CredentialOffer may be pre-authorized.
     */
    suspend fun getCredentialFromOffer(
        ctx: LoginContext,
        credOffer: CredentialOffer,
        loginCredentials: LoginCredentials? = null
    ): W3CCredentialJwt

    /**
     * Fetch the CredentialOffer for the given CredentialOfferUri
     */
    suspend fun getCredentialOfferFromUri(
        offerUri: String
    ): CredentialOffer

    /**
     * The Authorization Request parameter contains a DCQL query that describes the requirements of the Credential(s) that the Verifier is requesting to be presented.
     * Such requirements could include what type of Credential(s), in what format(s), which individual Claims within those Credential(s) (Selective Disclosure), etc.
     * The Wallet processes the Request Object and determines what Credentials are available matching the Verifier's request.
     * The Wallet also authenticates the End-User and gathers their consent to present the requested Credentials.
     *
     * The Wallet prepares the Presentation(s) of the Credential(s) that the End-User has consented to.
     * It then sends to the Verifier an Authorization Response where the Presentation(s) are contained in the vp_token parameter.
     *
     * https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-3
     */
    suspend fun handleVPTokenRequest(ctx: LoginContext, authReq: AuthorizationRequestV0): TokenResponse
}