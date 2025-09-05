package io.nessus.identity.service

import com.nimbusds.jwt.SignedJWT
import id.walt.oid4vc.data.CredentialOffer
import id.walt.oid4vc.requests.CredentialRequest
import id.walt.oid4vc.responses.CredentialResponse
import io.nessus.identity.config.ConfigProvider
import io.nessus.identity.types.CredentialParameters
import io.nessus.identity.types.IssuerMetadata
import io.nessus.identity.types.IssuerMetadataDraft11

// IssuerService =======================================================================================================

interface IssuerService {

    /**
     * Creates a CredentialOffer for the given subject and credential types.
     */
    suspend fun createCredentialOffer(
        ctx: LoginContext,
        subId: String,
        types: List<String>,
        userPin: String? = null
    ): CredentialOffer

    suspend fun getCredentialFromParameters(ctx: OIDContext, vcp: CredentialParameters): CredentialResponse

    suspend fun getCredentialFromRequest(
        ctx: OIDContext,
        credReq: CredentialRequest,
        accessTokenJwt: SignedJWT,
        deferred: Boolean = false
    ): CredentialResponse

    suspend fun getDeferredCredentialFromAcceptanceToken(
        ctx: OIDContext,
        acceptanceTokenJwt: SignedJWT
    ): CredentialResponse

    fun getIssuerMetadataUrl(ctx: LoginContext): String

    suspend fun <T : IssuerMetadata> getIssuerMetadata(ctx: LoginContext): T

    companion object {
        fun create(): IssuerService {
            val issuerUrl = ConfigProvider.issuerEndpointUri
            val authUrl = ConfigProvider.authEndpointUri
            return DefaultIssuerService(issuerUrl, authUrl);
        }
        fun createKeycloak(): IssuerService {
            return KeycloakIssuerService("https://auth.localtest.me/realms/oid4vci");
        }
    }
}
