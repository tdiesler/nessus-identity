package io.nessus.identity.service

import com.nimbusds.jwt.SignedJWT
import id.walt.oid4vc.data.dif.PresentationSubmission
import io.nessus.identity.config.ConfigProvider.requireEbsiConfig
import io.nessus.identity.config.ConfigProvider.requireWalletConfig
import io.nessus.identity.config.FeatureProfile.EBSI_V32
import io.nessus.identity.config.Features
import io.nessus.identity.types.AuthorizationMetadata
import io.nessus.identity.types.CredentialOffer
import io.nessus.identity.types.TokenResponse
import io.nessus.identity.types.W3CCredentialJwt

// WalletService =======================================================================================================

interface WalletService: CredentialAccessService, ExperimentalWalletService, LegacyWalletService {

    /**
     * The AuthorizationService
     */
    val authorizationSvc: AuthorizationService

    /**
     * The endpoint for this service
     */
    val endpointUri
        get() = when(Features.getProfile()) {
            EBSI_V32 -> "${requireEbsiConfig().baseUrl}/wallet"
            else -> requireWalletConfig().baseUrl
        }

    /** The Wallet authorization callback Uri */
    val authorizationCallbackUri
        get() = "$endpointUri/auth/callback"

    /**
     * Get the authorization metadata
     */
    fun getAuthorizationMetadata(ctx: LoginContext): AuthorizationMetadata

    /**
     * Gets an AccessToken for the offered Credential.
     *
     * This is a high-level entry method that involves the necessary authorization steps.
     * The CredentialOffer may be pre-authorized.
     */
    suspend fun getAccessTokenFromCredentialOffer(
        ctx: LoginContext,
        credOffer: CredentialOffer,
        clientId: String = defaultClientId,
    ): TokenResponse

    /**
     * Fetch the CredentialOffer for the given CredentialOfferUri
     */
    suspend fun getCredentialOfferFromUri(offerUri: String): CredentialOffer

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

    companion object {
        fun create(): WalletService {
            return NativeWalletService()
        }
    }
}

data class SubmissionBundle(
    val credentials: List<SignedJWT>,
    val submission: PresentationSubmission
)

