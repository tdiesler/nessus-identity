package io.nessus.identity.service

import com.nimbusds.jwt.SignedJWT
import id.walt.oid4vc.requests.CredentialRequest
import id.walt.oid4vc.responses.CredentialResponse
import io.nessus.identity.config.ConfigProvider
import io.nessus.identity.types.CredentialOffer
import io.nessus.identity.types.CredentialParameters
import io.nessus.identity.types.IssuerMetadata

// IssuerService =======================================================================================================

interface IssuerService<IMDType: IssuerMetadata> {

    companion object {
        /**
         * Creates the default IssuerService
         */
        fun create(ctx: OIDContext): DefaultIssuerService {
            val issuerUrl = ConfigProvider.issuerEndpointUri
            val authUrl = ConfigProvider.authEndpointUri
            return DefaultIssuerService(ctx, issuerUrl, authUrl);
        }
        /**
         * Creates the Keycloak IssuerService
         */
        fun createKeycloak(ctx: OIDContext): KeycloakIssuerService {
            return KeycloakIssuerService(ctx, "https://auth.localtest.me/realms/oid4vci");
        }
    }

    /**
     * Get the Issuer's metadata Url
     */
    fun getIssuerMetadataUrl(): String

    /**
     * Get the IssuerMetadata
     */
    suspend fun getIssuerMetadata(): IMDType

    /**
     * Creates a CredentialOffer for the given subject and credential types
     */
    suspend fun createCredentialOffer(
        subId: String,
        types: List<String>,
        userPin: String? = null,
    ): CredentialOffer

    suspend fun getCredentialFromParameters(
        vcp: CredentialParameters
    ): CredentialResponse

    suspend fun getCredentialFromRequest(
        credReq: CredentialRequest,
        accessTokenJwt: SignedJWT,
        deferred: Boolean = false,
    ): CredentialResponse

    suspend fun getDeferredCredentialFromAcceptanceToken(
        acceptanceTokenJwt: SignedJWT,
    ): CredentialResponse
}
