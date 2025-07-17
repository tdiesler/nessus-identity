package io.nessus.identity.service

import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.util.JSONObjectUtils
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import id.walt.oid4vc.OpenID4VCI
import id.walt.oid4vc.data.CredentialFormat
import id.walt.oid4vc.data.CredentialOffer
import id.walt.oid4vc.data.CredentialSupported
import id.walt.oid4vc.data.DisplayProperties
import id.walt.oid4vc.data.GrantType
import id.walt.oid4vc.data.OpenIDProviderMetadata
import id.walt.oid4vc.data.SubjectType
import id.walt.oid4vc.requests.CredentialRequest
import id.walt.oid4vc.responses.CredentialResponse
import io.github.oshai.kotlinlogging.KotlinLogging
import io.nessus.identity.api.IssuerServiceApi
import io.nessus.identity.config.ConfigProvider.authEndpointUri
import io.nessus.identity.config.ConfigProvider.issuerEndpointUri
import io.nessus.identity.types.CredentialSchema
import io.nessus.identity.types.JwtCredentialBuilder
import io.nessus.identity.types.W3CCredentialBuilder
import io.nessus.identity.waltid.WaltidServiceProvider.widWalletSvc
import io.nessus.identity.waltid.authenticationId
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import java.time.Instant
import java.util.Date
import kotlin.uuid.ExperimentalUuidApi
import kotlin.uuid.Uuid

// WalletService =======================================================================================================

object IssuerService : IssuerServiceApi {

    val log = KotlinLogging.logger {}

    override suspend fun createCredentialOffer(ctx: LoginContext, sub: String, types: List<String>): CredentialOffer {
        val metadata = getIssuerMetadata(ctx) as OpenIDProviderMetadata.Draft11
        val issuerUri = metadata.credentialIssuer as String

        // Build issuer state jwt
        val iat = Instant.now()
        val exp = iat.plusSeconds(300) // 5min
        val aud = metadata.authorizationServer
        val kid = ctx.didInfo.authenticationId()

        val header = JWSHeader.Builder(JWSAlgorithm.ES256)
            .type(JOSEObjectType.JWT)
            .keyID(kid)
            .build()
        val claims = JWTClaimsSet.Builder()
            .subject(sub)
            .audience(aud)
            .issueTime(Date.from(iat))
            .expirationTime(Date.from(exp))
            .claim("client_id", sub)
            .claim("credential_types", types)
            .build()
        val signingInput = Json.encodeToString(JWTUtils.createFlattenedJwsJson(header, claims))
        val issuerState = widWalletSvc.signWithKey(ctx, kid, signingInput)

        // Build CredentialOffer
        val vcJson = buildJsonObject {
            put("format", JsonPrimitive("jwt_vc"))
            put("types", JsonArray(types.map { JsonPrimitive(it) }))
        }
        val offer = CredentialOffer.Draft11.Builder(issuerUri)
            .addAuthorizationCodeGrant(issuerState)
            .addOfferedCredentialByValue(vcJson)
            .build()

        log.info { "Issuer State: $issuerState" }
        log.info { "Credential Offer: ${Json.encodeToString(offer)}" }

        return offer
    }

    @OptIn(ExperimentalUuidApi::class)
    override suspend fun getCredentialFromRequest(ctx: FlowContext, accessToken: String, credReq: CredentialRequest): CredentialResponse {

        val jwtToken = SignedJWT.parse(accessToken)
        ctx.validateAccessToken(jwtToken)

        log.info { "CredentialRequest: ${Json.encodeToString(credReq)}" }

        val id = "vc:nessus#${Uuid.random()}"
        val sub = ctx.authRequest.clientId
        val iat = Instant.now()
        val exp = iat.plusSeconds(86400)
        val types = credReq.types ?: throw IllegalArgumentException("No types in CredentialRequest")

        val supportedCredentials = getSupportedCredentials(ctx).flatMap { it.types.orEmpty() }.toSet()
        val unknownTypes = types.filterNot { it in supportedCredentials }
        if (unknownTypes.isNotEmpty())
            throw IllegalStateException("Unknown credential types: $unknownTypes")

        // [TODO] Derive CredentialSchema from somewhere
        val cred = JwtCredentialBuilder()
            .withId(id)
            .withIssuerId(ctx.did)
            .withSubjectId(sub)
            .withValidFrom(iat)
            .withValidUntil(exp)
            .withCredential(
                W3CCredentialBuilder()
                    .withCredentialSchema(
                        CredentialSchema(
                            "https://api-conformance.ebsi.eu/trusted-schemas-registry/v3/schemas/zDpWGUBenmqXzurskry9Nsk6vq2R8thh9VSeoRqguoyMD",
                            "FullJsonSchemaValidator2021"
                        )
                    )
                    .withId(id)
                    .withIssuer(ctx.did)
                    .withCredentialSubject(sub)
                    .withValidFrom(iat)
                    .withValidUntil(exp)
                    .withTypes(types)
                    .build()
            )
            .build()
        val credentialJson = Json.encodeToString(cred)

        val kid = ctx.didInfo.authenticationId()
        val credHeader = JWSHeader.Builder(JWSAlgorithm.ES256)
            .type(JOSEObjectType.JWT)
            .keyID(kid)
            .build()

        val credClaims = JWTClaimsSet.parse(JSONObjectUtils.parse(credentialJson))

        val rawCredentialJwt = SignedJWT(credHeader, credClaims)
        log.info { "Credential Header: ${rawCredentialJwt.header}" }
        log.info { "Credential Claims: ${rawCredentialJwt.jwtClaimsSet}" }

        val signingInput = Json.encodeToString(JWTUtils.createFlattenedJwsJson(credHeader, credClaims))
        val signedEncoded = widWalletSvc.signWithKey(ctx, kid, signingInput)
        val credentialJwt = SignedJWT.parse(signedEncoded)

        if (!JWTUtils.verifyJwt(credentialJwt, ctx.didInfo))
            throw IllegalStateException("Credential signature verification failed")

        val credentialResponse = CredentialResponse.success(CredentialFormat.jwt_vc, signedEncoded)
        log.info { "Credential Response: ${Json.encodeToString(credentialResponse)}" }

        return credentialResponse
    }

    override fun getIssuerMetadataUrl(ctx: LoginContext): String {
        val metadataUrl = OpenID4VCI.getCIProviderMetadataUrl("$issuerEndpointUri/${ctx.subjectId}")
        return metadataUrl
    }

    override fun getIssuerMetadata(ctx: LoginContext): OpenIDProviderMetadata {
        val metadata = buildIssuerMetadata(ctx)
        return metadata
    }

    override fun getSupportedCredentials(ctx: LoginContext): Set<CredentialSupported> {
        val md = getIssuerMetadata(ctx) as OpenIDProviderMetadata.Draft11
        val supported = md.credentialSupported?.values?.toSet() as Set
        return supported
    }
    // Private ---------------------------------------------------------------------------------------------------------

    private fun buildIssuerMetadata(ctx: LoginContext): OpenIDProviderMetadata {
        val baseUri = "$issuerEndpointUri/${ctx.subjectId}"
        val oauthUri = "$authEndpointUri/${ctx.subjectId}"
        val credentialSupported = mapOf(
            "CTWalletSameAuthorisedInTime" to CredentialSupported(
                format = CredentialFormat.jwt_vc,
                display = listOf(DisplayProperties(locale = "en-GB", name = "CTWalletSameAuthorisedInTime")),
                types = listOf("VerifiableCredential", "VerifiableAttestation", "CTWalletSameAuthorisedInTime")
            ),
            "CTWalletSameAuthorisedDeferred" to CredentialSupported(
                format = CredentialFormat.jwt_vc,
                display = listOf(DisplayProperties(locale = "en-GB", name = "CTWalletSameAuthorisedDeferred")),
                types = listOf("VerifiableCredential", "VerifiableAttestation", "CTWalletSameAuthorisedDeferred")
            ),
            "CTWalletSamePreAuthorisedInTime" to CredentialSupported(
                format = CredentialFormat.jwt_vc,
                display = listOf(DisplayProperties(locale = "en-GB", name = "CTWalletSamePreAuthorisedInTime")),
                types = listOf("VerifiableCredential", "VerifiableAttestation", "CTWalletSamePreAuthorisedInTime")
            ),
            "CTWalletSamePreAuthorisedDeferred" to CredentialSupported(
                format = CredentialFormat.jwt_vc,
                display = listOf(DisplayProperties(locale = "en-GB", name = "CTWalletSamePreAuthorisedDeferred")),
                types = listOf("VerifiableCredential", "VerifiableAttestation", "CTWalletSamePreAuthorisedDeferred")
            ),
        )
        return OpenIDProviderMetadata.Draft11.create(
            issuer = baseUri,
            authorizationServer = oauthUri,
            authorizationEndpoint = "$oauthUri/authorize",
            pushedAuthorizationRequestEndpoint = "$oauthUri/par",
            tokenEndpoint = "$oauthUri/token",
            credentialEndpoint = "$baseUri/credential",
            batchCredentialEndpoint = "$baseUri/batch_credential",
            deferredCredentialEndpoint = "$baseUri/credential_deferred",
            jwksUri = "$oauthUri/jwks",
            grantTypesSupported = setOf(GrantType.authorization_code, GrantType.pre_authorized_code),
            requestUriParameterSupported = true,
            subjectTypesSupported = setOf(SubjectType.public),
            credentialIssuer = baseUri,
            responseTypesSupported = setOf(
                "code",
                "vp_token",
                "id_token"
            ),
            idTokenSigningAlgValuesSupported = setOf("ES256"),
            codeChallengeMethodsSupported = listOf("S256"),
            credentialSupported = credentialSupported,
        )
    }
}