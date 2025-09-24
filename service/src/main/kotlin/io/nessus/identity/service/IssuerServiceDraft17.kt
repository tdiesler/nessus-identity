package io.nessus.identity.service

import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import io.ktor.client.call.body
import io.ktor.client.request.*
import io.nessus.identity.extend.signWithKey
import io.nessus.identity.service.CredentialOfferRegistry.putCredentialOfferRecord
import io.nessus.identity.types.AuthorizationCodeGrant
import io.nessus.identity.types.CredentialOfferDraft17
import io.nessus.identity.types.Grants
import io.nessus.identity.types.IssuerMetadataDraft17
import io.nessus.identity.types.PreAuthorizedCodeGrant
import io.nessus.identity.waltid.authenticationId
import java.net.URI
import java.time.Instant
import java.util.*

// KeycloakIssuerService =======================================================================================================================================

/**
 * Keycloak as OID4VC Issuer
 *
 * https://www.keycloak.org/docs/latest/server_admin/index.html#_oid4vci
 */
class IssuerServiceDraft17(ctx: OIDContext, issuerUrl: String)
    : AbstractIssuerService<IssuerMetadataDraft17, CredentialOfferDraft17>(ctx, issuerUrl) {

    override suspend fun createCredentialOffer(
        subId: String,
        types: List<String>,
        userPin: String?
    ): CredentialOfferDraft17 {

        val metadata = getIssuerMetadata()
        val issuerUri = metadata.credentialIssuer
        val supportedTypes = metadata.supportedTypes

        types.firstOrNull { it !in supportedTypes }?.let {
            throw IllegalArgumentException("UnsupportedType: $it")
        }

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
            .issuer(metadata.credentialIssuer)
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
                Grants(preAuthorizedCode = PreAuthorizedCodeGrant(preAuthorizedCode = preAuthCode))
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

    override suspend fun getIssuerMetadataInternal(): IssuerMetadataDraft17 {
        val metadataUrl = URI(getIssuerMetadataUrl()).toURL()
        val metadata = http.get(metadataUrl).body<IssuerMetadataDraft17>()
        return metadata
    }

    // Private ---------------------------------------------------------------------------------------------------------

}