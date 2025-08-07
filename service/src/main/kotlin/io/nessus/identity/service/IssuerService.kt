package io.nessus.identity.service

import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.util.JSONObjectUtils
import com.nimbusds.jwt.JWTClaimNames
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
import io.nessus.identity.config.ConfigProvider.authEndpointUri
import io.nessus.identity.config.ConfigProvider.issuerEndpointUri
import io.nessus.identity.extend.getPreAuthorizedGrantDetails
import io.nessus.identity.extend.signWithKey
import io.nessus.identity.extend.verifyJwtSignature
import io.nessus.identity.service.CredentialOfferRegistry.putCredentialOfferRecord
import io.nessus.identity.types.CredentialParameters
import io.nessus.identity.types.CredentialSchema
import io.nessus.identity.types.W3CCredentialBuilder
import io.nessus.identity.types.W3CCredentialJwtBuilder
import io.nessus.identity.waltid.authenticationId
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import java.time.Instant
import java.util.Date
import kotlin.uuid.ExperimentalUuidApi
import kotlin.uuid.Uuid

// IssuerService =======================================================================================================

object IssuerService {

    val log = KotlinLogging.logger {}

    // [TODO #231] Externalize pre-authorization code mapping
    val ebsiDefaultHolderId =
        "did:key:z2dmzD81cgPx8Vki7JbuuMmFYrWPgYoytykUZ3eyqht1j9Kboj7g9PfXJxbbs4KYegyr7ELnFVnpDMzbJJDDNZjavX6jvtDmALMbXAGW67pdTgFea2FrGGSFs8Ejxi96oFLGHcL4P6bjLDPBJEvRRHSrG4LsPne52fczt2MWjHLLJBvhAC"

    val defaultUserPin get() = run {
        System.getenv("EBSI__PREAUTHORIZED_PIN") ?: "1234"
    }

    suspend fun createCredentialOffer(ctx: LoginContext, subId: String, types: List<String>, userPin: String? = null): CredentialOffer {

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

        val offerClaims = JWTClaimsSet.Builder()
            .subject(subId)
            .audience(aud)
            .issuer(ctx.did)
            .issueTime(Date.from(iat))
            .expirationTime(Date.from(exp))
            .claim("client_id", subId)
            .claim("credential_types", types)
            .build()

        val credOfferJwt = SignedJWT(header, offerClaims).signWithKey(ctx, kid)

        // Build CredentialOffer
        val vcJson = buildJsonObject {
            put("format", JsonPrimitive("jwt_vc"))
            put("types", JsonArray(types.map { JsonPrimitive(it) }))
        }

        val offerBuilder = CredentialOffer.Draft11.Builder(issuerUri)
            .addOfferedCredentialByValue(vcJson)

        val credOffer = if (userPin != null) {
            val preAuthCode = credOfferJwt.serialize()
            offerBuilder.addPreAuthorizedCodeGrant(preAuthCode)
        } else {
            val issuerState = credOfferJwt.serialize()
            offerBuilder.addAuthorizationCodeGrant(issuerState)
        }.build()

        // Record the CredentialOffer with UserPin
        //
        val preAuthGrantDetails = credOffer.getPreAuthorizedGrantDetails()
        if (preAuthGrantDetails != null) {
            val authCode = preAuthGrantDetails.preAuthorizedCode as String
            putCredentialOfferRecord(authCode, credOffer, userPin)
        }

        log.info { "Issued CredentialOffer: ${Json.encodeToString(credOffer)}" }
        return credOffer
    }

    suspend fun credentialFromRequest(
        ctx: OIDCContext,
        credReq: CredentialRequest,
        accessTokenJwt: SignedJWT,
        deferred: Boolean = false,
    ): CredentialResponse {

        // Validate the AccessToken
        ctx.validateAccessToken(accessTokenJwt)

        log.info { "CredentialRequest: ${Json.encodeToString(credReq)}" }

        // Derive the deferred case from the CredentialRequest type
        //
        val deferredEBSIType = credReq.types?.any { it.startsWith("CT") && it.endsWith("Deferred") } == true
        val credentialResponse = if (deferred || deferredEBSIType) {
            credentialFromRequestDeferred(ctx, credReq)
        } else {
            val params = CredentialParameters()
                .withIssuer(ctx.did)
                .withSubject(ctx.authRequest.clientId)
                .withTypes(credReq.types!!)
            credentialFromParameters(ctx, params)
        }
        return credentialResponse
    }

    @OptIn(ExperimentalUuidApi::class)
    suspend fun credentialFromParameters(ctx: OIDCContext, vcp: CredentialParameters): CredentialResponse {

        val id = vcp.id ?: "vc:nessus#${Uuid.random()}"
        val iat = vcp.iat ?: Instant.now()
        val nbf = vcp.nbf ?: iat
        val exp = vcp.exp ?: iat.plusSeconds(86400) // 24h
        val iss = vcp.iss ?: ctx.did

        val sub = vcp.sub ?: throw java.lang.IllegalStateException("No subject")
        if (vcp.types.isEmpty())
            throw java.lang.IllegalStateException("No types")

        val supportedCredentials = getSupportedCredentials(ctx).flatMap { it.types.orEmpty() }.toSet()
        val unknownTypes = vcp.types.filterNot { it in supportedCredentials }
        if (unknownTypes.isNotEmpty())
            throw IllegalStateException("Unknown credential types: $unknownTypes")

        // [TODO #234] Derive CredentialSchema from somewhere
        val cred = W3CCredentialJwtBuilder()
            .withId(id)
            .withIssuerId(ctx.did)
            .withSubjectId(vcp.sub as String)
            .withIssuedAt(iat)
            .withValidFrom(nbf)
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
                    .withIssuer(iss)
                    .withCredentialSubject(sub)
                    .withIssuedAt(iat)
                    .withValidFrom(nbf)
                    .withValidUntil(exp)
                    .withTypes(vcp.types)
                    .build()
            )
            .build()

        val kid = ctx.didInfo.authenticationId()
        val credHeader = JWSHeader.Builder(JWSAlgorithm.ES256)
            .type(JOSEObjectType.JWT)
            .keyID(kid)
            .build()

        val credJson = Json.encodeToString(cred)
        val credClaims = JWTClaimsSet.parse(JSONObjectUtils.parse(credJson))

        val credJwt = SignedJWT(credHeader, credClaims).signWithKey(ctx, kid)
        log.info { "Credential Header: ${credJwt.header}" }
        log.info { "Credential Claims: ${credJwt.jwtClaimsSet}" }

        credJwt.verifyJwtSignature("Credential", ctx.didInfo)

        val credRes = CredentialResponse.success(CredentialFormat.jwt_vc, credJwt.serialize())
        log.info { "CredentialResponse: ${Json.encodeToString(credRes)}" }

        return credRes
    }

    suspend fun deferredCredentialFromAcceptanceToken(ctx: OIDCContext, acceptanceTokenJwt: SignedJWT): CredentialResponse {

        // Validate the AcceptanceTokenJwt
        // [TODO #241] Validate the AcceptanceToken

        // Derive the deferred case from the CredentialRequest type
        //
        log.info { "AcceptanceToken Header: ${acceptanceTokenJwt.header}" }
        log.info { "AcceptanceToken Claims: ${acceptanceTokenJwt.jwtClaimsSet}" }

        val credReqJson = acceptanceTokenJwt.jwtClaimsSet.getClaim("credential_request") as String
        val credReq = Json.decodeFromString<CredentialRequest>(credReqJson)
        val params = CredentialParameters()
            .withIssuer(ctx.did)
            .withSubject(ctx.authRequest.clientId)
            .withTypes(credReq.types!!)
        val credentialResponse = credentialFromParameters(ctx, params)

        return credentialResponse
    }

    fun getIssuerMetadataUrl(ctx: LoginContext): String {
        val metadataUrl = OpenID4VCI.getCIProviderMetadataUrl("$issuerEndpointUri/${ctx.targetId}")
        return metadataUrl
    }

    fun getIssuerMetadata(ctx: LoginContext): OpenIDProviderMetadata {
        val metadata = buildIssuerMetadata(ctx)
        return metadata
    }

    fun getSupportedCredentials(ctx: LoginContext): Set<CredentialSupported> {
        val md = getIssuerMetadata(ctx) as OpenIDProviderMetadata.Draft11
        val supported = md.credentialSupported?.values?.toSet() as Set
        return supported
    }
    // Private ---------------------------------------------------------------------------------------------------------

    private fun buildIssuerMetadata(ctx: LoginContext): OpenIDProviderMetadata {
        val baseUri = "$issuerEndpointUri/${ctx.targetId}"
        val oauthUri = "$authEndpointUri/${ctx.targetId}"
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

    @OptIn(ExperimentalUuidApi::class)
    private suspend fun credentialFromRequestDeferred(
        ctx: OIDCContext,
        credReq: CredentialRequest,
    ): CredentialResponse {

        log.info { "CredentialRequestDeferred: ${Json.encodeToString(credReq)}" }

        val types = credReq.types ?: throw IllegalArgumentException("No types in CredentialRequest")
        val supportedCredentials = getSupportedCredentials(ctx).flatMap { it.types.orEmpty() }.toSet()
        val unknownTypes = types.filterNot { it in supportedCredentials }
        if (unknownTypes.isNotEmpty())
            throw IllegalStateException("Unknown credential types: $unknownTypes")

        val jti = "vc:nessus#${Uuid.random()}"
        val sub = ctx.authRequest.clientId
        val nbf = Instant.now().plusSeconds(5)

        val kid = ctx.didInfo.authenticationId()
        val acceptanceHeader = JWSHeader.Builder(JWSAlgorithm.ES256)
            .type(JOSEObjectType.JWT)
            .keyID(kid)
            .build()

        val acceptanceClaims = JWTClaimsSet.parse(mapOf(
            JWTClaimNames.JWT_ID to jti,
            JWTClaimNames.ISSUER to ctx.did,
            JWTClaimNames.SUBJECT to sub,
            JWTClaimNames.NOT_BEFORE to nbf.epochSecond,
            "credential_request" to Json.encodeToString(credReq)
        ))

        val acceptanceTokenJwt = SignedJWT(acceptanceHeader, acceptanceClaims).signWithKey(ctx, kid)
        log.info { "AcceptanceToken Header: ${acceptanceTokenJwt.header}" }
        log.info { "AcceptanceToken Claims: ${acceptanceTokenJwt.jwtClaimsSet}" }

        acceptanceTokenJwt.verifyJwtSignature("AcceptanceToken", ctx.didInfo)

        val credentialResponse = CredentialResponse.deferred(CredentialFormat.jwt_vc, acceptanceTokenJwt.serialize())
        log.info { "CredentialResponseDeferred: ${Json.encodeToString(credentialResponse)}" }

        return credentialResponse
    }
}