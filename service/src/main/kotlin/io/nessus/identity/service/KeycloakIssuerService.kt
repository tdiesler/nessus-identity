package io.nessus.identity.service

import com.nimbusds.jwt.SignedJWT
import id.walt.oid4vc.data.CredentialOffer
import id.walt.oid4vc.requests.CredentialRequest
import id.walt.oid4vc.responses.CredentialResponse
import io.github.oshai.kotlinlogging.KotlinLogging
import io.ktor.client.request.*
import io.ktor.client.statement.*
import io.nessus.identity.types.CredentialParameters
import io.nessus.identity.types.IssuerMetadata
import io.nessus.identity.types.IssuerMetadataDraft11
import io.nessus.identity.types.IssuerMetadataDraft17
import java.net.URI
import kotlin.uuid.ExperimentalUuidApi

// IssuerService =======================================================================================================

class KeycloakIssuerService(issuerUrl: String) : AbstractIssuerService(issuerUrl) {

    val log = KotlinLogging.logger {}

    override suspend fun createCredentialOffer(ctx: LoginContext, subId: String, types: List<String>, userPin: String?): CredentialOffer {
        throw IllegalStateException("Not implemented")
    }

    override suspend fun getCredentialFromRequest(ctx: OIDContext, credReq: CredentialRequest, accessTokenJwt: SignedJWT, deferred: Boolean): CredentialResponse {
        throw IllegalStateException("Not implemented")
    }

    @OptIn(ExperimentalUuidApi::class)
    override suspend fun getCredentialFromParameters(ctx: OIDContext, vcp: CredentialParameters): CredentialResponse {
        throw IllegalStateException("Not implemented")
    }

    override suspend fun getDeferredCredentialFromAcceptanceToken(ctx: OIDContext, acceptanceTokenJwt: SignedJWT): CredentialResponse {
        throw IllegalStateException("Not implemented")
    }

    @Suppress("UNCHECKED_CAST")
    override suspend fun <T : IssuerMetadata> getIssuerMetadata(ctx: LoginContext): T {
        val metadataUrl = URI(getIssuerMetadataUrl(ctx)).toURL()
        val metadata = http.get(metadataUrl).bodyAsText().let {
            IssuerMetadataDraft17.fromJson(it)
        }
        return metadata as T
    }

    // Private ---------------------------------------------------------------------------------------------------------

}