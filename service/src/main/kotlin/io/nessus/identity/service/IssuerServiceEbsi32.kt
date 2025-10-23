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
import id.walt.oid4vc.data.CredentialSupported
import id.walt.oid4vc.data.DisplayProperties
import id.walt.oid4vc.data.GrantType
import id.walt.oid4vc.data.OpenIDProviderMetadata
import id.walt.oid4vc.data.SubjectType
import id.walt.oid4vc.requests.CredentialRequest
import id.walt.oid4vc.responses.CredentialResponse
import io.nessus.identity.extend.signWithKey
import io.nessus.identity.extend.verifyJwtSignature
import io.nessus.identity.service.CredentialOfferRegistry.putCredentialOfferRecord
import io.nessus.identity.types.AuthorizationCodeGrant
import io.nessus.identity.types.CredentialObject
import io.nessus.identity.types.CredentialOfferDraft11
import io.nessus.identity.types.CredentialParameters
import io.nessus.identity.types.CredentialSchema
import io.nessus.identity.types.Grants
import io.nessus.identity.types.IssuerMetadataDraft11
import io.nessus.identity.types.PreAuthorizedCodeGrant
import io.nessus.identity.types.VCDataV11Builder
import io.nessus.identity.types.VCDataV11JwtBuilder
import io.nessus.identity.waltid.authenticationId
import kotlinx.serialization.json.*
import java.time.Instant
import java.util.*
import kotlin.time.Clock
import kotlin.time.Duration.Companion.hours
import kotlin.uuid.Uuid

// DefaultIssuerService ================================================================================================

class IssuerServiceEbsi32(issuerUrl: String, val authUrl: String) : AbstractIssuerService<IssuerMetadataDraft11>(issuerUrl) {

    /**
     * Creates a CredentialOffer for the given subject and credential types
     */
    suspend fun createCredentialOffer(
        ctx: LoginContext,
        subjectId: String,
        types: List<String>,
        userPin: String? = null
    ): CredentialOfferDraft11 {

        val metadata = getIssuerMetadata(ctx)
        val issuerUri = metadata.credentialIssuer

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
            .subject(subjectId)
            .audience(aud)
            .issuer(ctx.did)
            .issueTime(Date.from(iat))
            .expirationTime(Date.from(exp))
            .claim("client_id", subjectId)
            .claim("credential_types", types)
            .build()

        val credOfferJwt = SignedJWT(header, offerClaims).signWithKey(ctx, kid)

        // Build CredentialOffer
        val credOffer = CredentialOfferDraft11(
            credentialIssuer = issuerUri,
            credentials = listOf(CredentialObject(types = types, format = "jwt_vc")),
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

    suspend fun getCredentialFromRequest(
        ctx: OIDContext,
        credReq: CredentialRequest,
        accessTokenJwt: SignedJWT,
        deferred: Boolean = false
    ): CredentialResponse {

        // Validate the AccessToken
        validateAccessToken(accessTokenJwt)

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
            getCredentialFromParameters(ctx, params)
        }
        return credentialResponse
    }

    suspend fun getCredentialFromParameters(
        ctx: OIDContext,
        vcp: CredentialParameters
    ): CredentialResponse {

        // Init property defaults when not given
        //
        val id = vcp.id ?: "vc:nessus#${Uuid.random()}"
        val iat = vcp.iat ?: Clock.System.now()
        val nbf = vcp.nbf ?: iat
        val exp = vcp.exp ?: (iat + 24.hours)
        val iss = vcp.iss ?: ctx.did

        // Verify required properties
        //
        val sub = vcp.sub ?: throw java.lang.IllegalStateException("No subject")
        if (vcp.types.isEmpty())
            throw java.lang.IllegalStateException("No types")

        // Verify credential types i.e. every type must bve known to this issuer
        val metadata = getIssuerMetadata(ctx)
        val supportedCredentials = metadata.credentialsSupported.flatMap { it.types.orEmpty() }.toSet()
        val unknownTypes = vcp.types.filterNot { it in supportedCredentials }
        if (unknownTypes.isNotEmpty())
            throw IllegalStateException("Unknown credential types: $unknownTypes")

        val cred = VCDataV11JwtBuilder()
            .withId(id)
            .withIssuerId(ctx.did)
            .withSubjectId(vcp.sub as String)
            .withIssuedAt(iat)
            .withValidFrom(nbf)
            .withValidUntil(exp)
            .withCredential(
                VCDataV11Builder()
                    .withCredentialSchema(
                        CredentialSchema(
                            "https://api-conformance.ebsi.eu/trusted-schemas-registry/v3/schemas/zDpWGUBenmqXzurskry9Nsk6vq2R8thh9VSeoRqguoyMD",
                            "FullJsonSchemaValidator2021"
                        )
                    )
                    .withId(id)
                    .withIssuer(iss)
                    .withCredentialStatus(vcp.status)
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

    suspend fun getDeferredCredentialFromAcceptanceToken(
        ctx: OIDContext,
        acceptanceTokenJwt: SignedJWT
    ): CredentialResponse {

        // Validate the AcceptanceTokenJwt
        // [TODO #241] Validate the AcceptanceToken
        // https://github.com/tdiesler/nessus-identity/issues/241

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
        val credentialResponse = getCredentialFromParameters(ctx, params)

        return credentialResponse
    }

    override fun getIssuerMetadataUrl(): String {
        throw IllegalStateException("Not implemented")
    }

    override suspend fun getIssuerMetadata(): IssuerMetadataDraft11 {
        throw IllegalStateException("Not implemented")
    }

    fun getIssuerMetadataUrl(ctx: LoginContext): String {
        val metadataUrl = OpenID4VCI.getCIProviderMetadataUrl("$issuerUrl/${ctx.targetId}")
        return metadataUrl
    }

    fun getIssuerMetadata(ctx: LoginContext): IssuerMetadataDraft11 {
        val authTargetUrl = "$authUrl/${ctx.targetId}"
        val issuerTargetUrl = "$issuerUrl/${ctx.targetId}"
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
        val waltDraft11 = OpenIDProviderMetadata.Draft11.create(
            issuer = issuerTargetUrl,
            authorizationServer = authTargetUrl,
            authorizationEndpoint = "$authTargetUrl/authorize",
            pushedAuthorizationRequestEndpoint = "$authTargetUrl/par",
            tokenEndpoint = "$authTargetUrl/token",
            credentialEndpoint = "$issuerTargetUrl/credential",
            batchCredentialEndpoint = "$issuerTargetUrl/batch_credential",
            deferredCredentialEndpoint = "$issuerTargetUrl/credential_deferred",
            jwksUri = "$authTargetUrl/jwks",
            grantTypesSupported = setOf(GrantType.authorization_code, GrantType.pre_authorized_code),
            requestUriParameterSupported = true,
            subjectTypesSupported = setOf(SubjectType.public),
            credentialIssuer = issuerTargetUrl,
            responseTypesSupported = setOf(
                "code",
                "vp_token",
                "id_token"
            ),
            idTokenSigningAlgValuesSupported = setOf("ES256"),
            codeChallengeMethodsSupported = listOf("S256"),
            credentialSupported = credentialSupported,
        )
        val metadata = IssuerMetadataDraft11.fromJson(waltDraft11.toJSONString())
        return metadata
    }

    // Private ---------------------------------------------------------------------------------------------------------

    private suspend fun credentialFromRequestDeferred(
        ctx: OIDContext,
        credReq: CredentialRequest,
    ): CredentialResponse {

        log.info { "CredentialRequestDeferred: ${Json.encodeToString(credReq)}" }

        val types = credReq.types ?: throw IllegalArgumentException("No types in CredentialRequest")
        val metadata = getIssuerMetadata(ctx)
        val supportedCredentials = metadata.credentialsSupported.flatMap { it.types.orEmpty() }.toSet()
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

        val acceptanceClaims = JWTClaimsSet.parse(
            mapOf(
                JWTClaimNames.JWT_ID to jti,
                JWTClaimNames.ISSUER to ctx.did,
                JWTClaimNames.SUBJECT to sub,
                JWTClaimNames.NOT_BEFORE to nbf.epochSecond,
                "credential_request" to Json.encodeToString(credReq)
            )
        )

        val acceptanceTokenJwt = SignedJWT(acceptanceHeader, acceptanceClaims).signWithKey(ctx, kid)
        log.info { "AcceptanceToken Header: ${acceptanceTokenJwt.header}" }
        log.info { "AcceptanceToken Claims: ${acceptanceTokenJwt.jwtClaimsSet}" }

        acceptanceTokenJwt.verifyJwtSignature("AcceptanceToken", ctx.didInfo)

        val credentialResponse = CredentialResponse.deferred(CredentialFormat.jwt_vc, acceptanceTokenJwt.serialize())
        log.info { "CredentialResponseDeferred: ${Json.encodeToString(credentialResponse)}" }

        return credentialResponse
    }

    fun validateAccessToken(bearerToken: SignedJWT) {

        val claims = bearerToken.jwtClaimsSet
        val exp = claims.expirationTime?.toInstant()
        if (exp == null || exp.isBefore(Instant.now()))
            throw IllegalStateException("Token expired")

        // [TODO #235] Properly validate the AccessToken
        // https://github.com/tdiesler/nessus-identity/issues/235
    }
}