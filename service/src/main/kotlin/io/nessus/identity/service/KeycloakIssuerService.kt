package io.nessus.identity.service

import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import id.walt.oid4vc.requests.CredentialRequest
import id.walt.oid4vc.responses.CredentialResponse
import io.github.oshai.kotlinlogging.KotlinLogging
import io.ktor.client.request.*
import io.ktor.client.statement.*
import io.nessus.identity.extend.signWithKey
import io.nessus.identity.service.CredentialOfferRegistry.putCredentialOfferRecord
import io.nessus.identity.types.AuthorizationCodeGrant
import io.nessus.identity.types.CredentialOfferDraft17
import io.nessus.identity.types.CredentialParameters
import io.nessus.identity.types.Grants
import io.nessus.identity.types.IssuerMetadata
import io.nessus.identity.types.IssuerMetadataDraft17
import io.nessus.identity.types.PreAuthorizedCodeGrant
import io.nessus.identity.waltid.authenticationId
import java.net.URI
import java.time.Instant
import java.util.*
import kotlin.uuid.ExperimentalUuidApi

// IssuerService =======================================================================================================

class KeycloakIssuerService(issuerUrl: String) : AbstractIssuerService(issuerUrl) {

    val log = KotlinLogging.logger {}

    override suspend fun createCredentialOffer(ctx: LoginContext, subId: String, types: List<String>, userPin: String?): CredentialOfferDraft17 {

        val metadata = getIssuerMetadata(ctx) as IssuerMetadataDraft17
        val issuerUri = metadata.credentialIssuer

        // Build issuer state jwt
        val iat = Instant.now()
        val exp = iat.plusSeconds(300) // 5min
        val kid = ctx.didInfo.authenticationId()

        val header = JWSHeader.Builder(JWSAlgorithm.ES256)
            .type(JOSEObjectType.JWT)
            .keyID(kid)
            .build()

        val offerClaims = JWTClaimsSet.Builder()
            .subject(subId)
            .issuer(ctx.did)
            .issueTime(Date.from(iat))
            .expirationTime(Date.from(exp))
            .claim("client_id", subId)
            .claim("credential_types", types)
            .build()

        val credOfferJwt = SignedJWT(header, offerClaims).signWithKey(ctx, kid)

        // Build CredentialOffer
        val credOffer = CredentialOfferDraft17(
            credentialIssuer = issuerUri,
            credentialConfigurationIds = types,
            grants = if (userPin != null) {
                val preAuthCode = credOfferJwt.serialize()
                Grants(preAuthorizedCode=PreAuthorizedCodeGrant(preAuthorizedCode = preAuthCode))
            } else {
                val issuerState = credOfferJwt.serialize()
                Grants(authorizationCode = AuthorizationCodeGrant(issuerState = issuerState))
            }
        )

        // Record the CredentialOffer with UserPin
        //
        val preAuthCodeGrant = credOffer.getPreAuthorizedCodeGrant()
        if (preAuthCodeGrant != null) {
            val authCode = preAuthCodeGrant.preAuthorizedCode
            putCredentialOfferRecord(authCode, credOffer, userPin)
        }

        log.info { "Issued CredentialOffer: ${credOffer.toJson()}" }
        return credOffer
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