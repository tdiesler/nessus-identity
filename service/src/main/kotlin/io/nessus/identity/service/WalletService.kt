package io.nessus.identity.service

import io.nessus.identity.LoginContext
import io.nessus.identity.config.ConfigProvider.requireWalletConfig
import io.nessus.identity.config.FeatureProfile.EBSI_V32
import io.nessus.identity.config.Features
import io.nessus.identity.types.CredentialOffer
import io.nessus.identity.types.TokenResponse
import io.nessus.identity.types.W3CCredentialJwt

interface WalletService: ExperimentalWalletService, LegacyWalletService, WalletCredentialsService {

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
}