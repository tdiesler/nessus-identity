package io.nessus.identity.service

import com.nimbusds.jwt.SignedJWT
import id.walt.oid4vc.requests.CredentialRequest
import id.walt.oid4vc.responses.CredentialResponse
import io.nessus.identity.config.ConfigProvider
import io.nessus.identity.types.CredentialOffer
import io.nessus.identity.types.CredentialParameters
import io.nessus.identity.types.IssuerMetadata

// IssuerService =======================================================================================================

interface IssuerService<COType: CredentialOffer, IMDType: IssuerMetadata> {

    /**
     * Creates a CredentialOffer for the given subject and credential types.
     */
    suspend fun createCredentialOffer(
        ctx: LoginContext,
        subId: String,
        types: List<String>,
        userPin: String? = null
    ): COType

    suspend fun getCredentialFromParameters(
        ctx: OIDContext,
        vcp: CredentialParameters
    ): CredentialResponse

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

    suspend fun getIssuerMetadata(ctx: LoginContext): IMDType

    companion object {
        fun create(): DefaultIssuerService {
            val issuerUrl = ConfigProvider.issuerEndpointUri
            val authUrl = ConfigProvider.authEndpointUri
            return DefaultIssuerService(issuerUrl, authUrl);
        }
        fun createKeycloak(): KeycloakIssuerService {
            return KeycloakIssuerService("https://auth.localtest.me/realms/oid4vci");
        }
    }
}
