package io.nessus.identity.service

import com.nimbusds.jwt.SignedJWT
import io.nessus.identity.AuthorizationContext
import io.nessus.identity.Experimental
import io.nessus.identity.Legacy
import io.nessus.identity.LoginContext
import io.nessus.identity.config.ConfigProvider.requireWalletConfig
import io.nessus.identity.config.FeatureProfile.EBSI_V32
import io.nessus.identity.config.Features
import io.nessus.identity.types.AuthorizationRequest
import io.nessus.identity.types.AuthorizationRequestV0
import io.nessus.identity.types.CredentialOffer
import io.nessus.identity.types.CredentialRequest
import io.nessus.identity.types.DCQLQuery
import io.nessus.identity.types.SubmissionBundle
import io.nessus.identity.types.TokenRequest
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
     * Gets an AccessToken from a CredentialOffer.
     *
     * This is a high-level entry method that involves a number of authorization steps.
     * The CredentialOffer may be pre-authorized.
     */
    suspend fun authorizeFromCredentialOffer(
        ctx: LoginContext,
        credOffer: CredentialOffer,
        clientId: String = defaultClientId,
    ): TokenResponse

    suspend fun authorizeWithDirectAccess(
        ctx: LoginContext,
        clientId: String = defaultClientId,
    ): TokenResponse

    /**
     * The Wallet fetches a Credential for the given AccessToken
     */
    suspend fun getCredential(ctx: LoginContext, accessToken: TokenResponse): W3CCredentialJwt

    /**
     * The Wallet gets the Credential for the given CredentialOffer
     *
     * This is a high-level entry method that involves the necessary authorization steps.
     * The CredentialOffer may be pre-authorized.
     */
    suspend fun getCredentialFromOffer(ctx: LoginContext, credOffer: CredentialOffer): W3CCredentialJwt

    /**
     * Fetch the CredentialOffer for the given CredentialOfferUri
     */
    suspend fun getCredentialOfferFromUri(offerUri: String): CredentialOffer

    // ExperimentalWalletService =======================================================================================

    @Experimental
    suspend fun buildAuthorizationRequestFromOffer(
        ctx: LoginContext,
        credOffer: CredentialOffer
    ): AuthorizationRequest

    @Experimental
    suspend fun buildCredentialRequest(
        ctx: LoginContext,
        authRequest: AuthorizationRequest
    ): CredentialRequest

    @Experimental
    suspend fun createIDToken(
        ctx: LoginContext, authRequest:
        AuthorizationRequest
    ): SignedJWT

    @Experimental
    suspend fun getAccessTokenFromCode(
        ctx: LoginContext,
        authCode: String,
    ): TokenResponse

    @Experimental
    suspend fun getTokenRequestFromAuthorizationCode(
        ctx: LoginContext,
        authCode: String
    ): TokenRequest

    @Experimental
    suspend fun sendAuthorizationRequest(
        ctx: LoginContext,
        authEndpointUri: String,
        authRequest: AuthorizationRequest,
    ): String

    @Experimental
    suspend fun sendTokenRequest(
        ctx: LoginContext,
        tokenRequest: TokenRequest
    ): TokenResponse

    // LegacyWalletService =============================================================================================

    @Legacy
    @Deprecated("promote or remove")
    suspend fun buildAuthorizationRequest(
        authContext: AuthorizationContext,
        clientId: String = defaultClientId,
        redirectUri: String = "urn:ietf:wg:oauth:2.0:oob"
    ): AuthorizationRequestV0

    @Legacy
    @Deprecated("promote or remove")
    suspend fun buildPresentationSubmission(
        ctx: LoginContext,
        dcql: DCQLQuery,
    ): SubmissionBundle

    @Legacy
    @Deprecated("promote or remove")
    suspend fun getAuthorizationCode(
        ctx: LoginContext,
        clientId: String = defaultClientId,
        username: String,
        password: String,
        redirectUri: String = "urn:ietf:wg:oauth:2.0:oob"
    ): String

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
    @Legacy
    @Deprecated("promote or remove")
    suspend fun handleVPTokenRequest(ctx: LoginContext, authReq: AuthorizationRequestV0): TokenResponse
}