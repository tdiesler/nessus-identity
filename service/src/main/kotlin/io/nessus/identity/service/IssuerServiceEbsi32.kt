package io.nessus.identity.service

import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.util.JSONObjectUtils
import com.nimbusds.jwt.JWTClaimNames
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import id.walt.oid4vc.data.CredentialFormat
import id.walt.oid4vc.data.CredentialSupported
import id.walt.oid4vc.data.DisplayProperties
import id.walt.oid4vc.data.GrantType
import id.walt.oid4vc.data.OpenIDProviderMetadata
import id.walt.oid4vc.data.SubjectType
import io.nessus.identity.config.IssuerConfig
import io.nessus.identity.config.User
import io.nessus.identity.extend.signWithKey
import io.nessus.identity.extend.verifyJwtSignature
import io.nessus.identity.service.AuthorizationContext.Companion.EBSI32_AUTHORIZATION_REQUEST_DRAFT11_ATTACHMENT_KEY
import io.nessus.identity.service.AuthorizationContext.Companion.EBSI32_ISSUER_METADATA_ATTACHMENT_KEY
import io.nessus.identity.service.CredentialOfferRegistry.putCredentialOfferRecord
import io.nessus.identity.service.UserAccessService.UserInfo
import io.nessus.identity.types.AuthorizationCodeGrant
import io.nessus.identity.types.AuthorizationMetadata
import io.nessus.identity.types.AuthorizationRequest
import io.nessus.identity.types.AuthorizationRequestDraft11
import io.nessus.identity.types.CredentialObject
import io.nessus.identity.types.CredentialOffer
import io.nessus.identity.types.CredentialOfferDraft11
import io.nessus.identity.types.CredentialParameters
import io.nessus.identity.types.CredentialRequest
import io.nessus.identity.types.CredentialRequestDraft11
import io.nessus.identity.types.CredentialResponse
import io.nessus.identity.types.CredentialSchema
import io.nessus.identity.types.Grants
import io.nessus.identity.types.IssuerMetadataDraft11
import io.nessus.identity.types.PreAuthorizedCodeGrant
import io.nessus.identity.types.TokenRequest
import io.nessus.identity.types.TokenResponse
import io.nessus.identity.types.VCDataV11JwtBuilder
import io.nessus.identity.types.W3CCredentialV11Builder
import io.nessus.identity.waltid.authenticationId
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.*
import java.time.Instant
import java.util.*
import kotlin.time.Clock
import kotlin.time.Duration.Companion.hours
import kotlin.uuid.Uuid

// IssuerServiceEbsi32 =================================================================================================

typealias WaltIdCredentialResponse = id.walt.oid4vc.responses.CredentialResponse

class IssuerServiceEbsi32(val config: IssuerConfig) : AbstractIssuerService(), IssuerService {

    private var adminContext: LoginContext

    override val authorizationSvc = AuthorizationService.create()

    init {
        runBlocking {
            adminContext = LoginContext.login(config.adminUser).withDidInfo()
        }
    }

    /**
     * Get the authorization metadata
     */
    override suspend fun getAuthorizationMetadata(): AuthorizationMetadata {
        val targetUri = "$endpointUri/${adminContext.targetId}"
        return authorizationSvc.buildAuthorizationMetadata(targetUri)
    }

    override suspend fun createCredentialOfferUri(
        configId: String,
        clientId: String?,
        preAuthorized: Boolean,
        userPin: String?,
        targetUser: User?,
    ): String {
        error("Not implemented")
    }

    override suspend fun createCredentialOffer(
        configId: String,
        clientId: String?,
        preAuthorized: Boolean,
        userPin: String?,
        targetUser: User?,
    ): CredentialOffer {

        val ctx = adminContext
        val issuerMetadata = getIssuerMetadata()
        val issuerUri = issuerMetadata.credentialIssuer

        val credConfig = issuerMetadata.credentialsSupported.first { it.types!!.contains(configId) }
        val ctypes = requireNotNull(credConfig.types) { "No types " }

        // Build issuer state jwt
        val iat = Instant.now()
        val exp = iat.plusSeconds(300) // 5min
        val aud = issuerMetadata.authorizationServer
        val kid = ctx.didInfo.authenticationId()

        val header = JWSHeader.Builder(JWSAlgorithm.ES256).type(JOSEObjectType.JWT).keyID(kid).build()

        val offerClaims =
            JWTClaimsSet.Builder().subject(clientId).audience(aud).issuer(ctx.did).issueTime(Date.from(iat))
                .expirationTime(Date.from(exp)).claim("client_id", clientId).claim("credential_types", ctypes).build()

        val credOfferJwt = SignedJWT(header, offerClaims).signWithKey(ctx, kid)

        // Build CredentialOffer
        val credOffer = CredentialOfferDraft11(
            credentialIssuer = issuerUri,
            credentials = listOf(CredentialObject(types = ctypes, format = credConfig.format)),
            grants = if (preAuthorized) {
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

    override suspend fun createIDTokenRequest(
        ctx: LoginContext, authRequest: AuthorizationRequest
    ): AuthorizationRequest {

        val authContext = ctx.getAuthContext()
        authRequest as AuthorizationRequestDraft11
        authContext.putAttachment(EBSI32_ISSUER_METADATA_ATTACHMENT_KEY, getIssuerMetadata())
        authContext.putAttachment(EBSI32_AUTHORIZATION_REQUEST_DRAFT11_ATTACHMENT_KEY, authRequest)

        val targetEndpointUri = "${endpointUri}/${adminContext.targetId}"
        val redirectUri = requireNotNull(authRequest.redirectUri) { "No redirect_uri" }
        val idTokenRequestJwt = authorizationSvc.createIDTokenRequestJwt(ctx, targetEndpointUri, authRequest)
        val authRequestOut = authorizationSvc.buildIDTokenAuthorizationRequest(redirectUri, idTokenRequestJwt)

        return authRequestOut
    }

    override fun getAuthCodeFromIDToken(
        ctx: LoginContext,
        idTokenJwt: SignedJWT,
    ): String {
        val redirectUrl = authorizationSvc.getIDTokenRedirectUrl(ctx, idTokenJwt)
        val authCode = getAuthCodeFromRedirectUrl(redirectUrl)
        return authCode
    }

    override suspend fun getTokenResponse(
        ctx: LoginContext, tokenRequest: TokenRequest
    ): TokenResponse {
        val issuerMetadata = getIssuerMetadata()
        ctx.getAuthContext().putAttachment(EBSI32_ISSUER_METADATA_ATTACHMENT_KEY, issuerMetadata)
        return authorizationSvc.getTokenResponse(ctx, tokenRequest)
    }

    override suspend fun getNativeCredentialFromRequest(
        ctx: LoginContext, credReq: CredentialRequest, accessTokenJwt: SignedJWT, deferred: Boolean
    ): CredentialResponse {

        // Validate the AccessToken
        authorizationSvc.validateAccessToken(accessTokenJwt)

        log.info { "CredentialRequest: ${Json.encodeToString(credReq)}" }

        // Derive the deferred case from the CredentialRequest type
        //
        credReq as CredentialRequestDraft11
        val deferredEBSIType = credReq.types?.any { it.startsWith("CT") && it.endsWith("Deferred") } == true
        val credentialResponse = if (deferred || deferredEBSIType) {
            getNativeCredentialFromRequestDeferred(ctx, credReq)
        } else {
            val authContext = ctx.getAuthContext()
            val authRequest = authContext.assertAttachment(EBSI32_AUTHORIZATION_REQUEST_DRAFT11_ATTACHMENT_KEY)
            val params =
                CredentialParameters().withIssuer(ctx.did).withSubject(authRequest.clientId).withTypes(credReq.types!!)
            getCredentialFromParameters(ctx, params)
        }
        return credentialResponse
    }

    override suspend fun getNativeCredentialFromAcceptanceToken(
        ctx: LoginContext, acceptanceTokenJwt: SignedJWT
    ): CredentialResponse {

        // Validate the AcceptanceTokenJwt
        // [TODO #241] Validate the AcceptanceToken
        // https://github.com/tdiesler/nessus-identity/issues/241

        // Derive the deferred case from the CredentialRequestV0 type
        //
        log.info { "AcceptanceToken Header: ${acceptanceTokenJwt.header}" }
        log.info { "AcceptanceToken Claims: ${acceptanceTokenJwt.jwtClaimsSet}" }

        val authContext = ctx.getAuthContext()
        val authRequest = authContext.assertAttachment(EBSI32_AUTHORIZATION_REQUEST_DRAFT11_ATTACHMENT_KEY)

        val credReqJson = acceptanceTokenJwt.jwtClaimsSet.getClaim("credential_request") as String
        val credReq = Json.decodeFromString<CredentialRequestDraft11>(credReqJson)
        val params =
            CredentialParameters().withIssuer(ctx.did).withSubject(authRequest.clientId).withTypes(credReq.types!!)
        val credentialResponse = getCredentialFromParameters(ctx, params)

        return credentialResponse
    }

    private suspend fun getNativeCredentialFromRequestDeferred(
        ctx: LoginContext,
        credReq: CredentialRequest,
    ): CredentialResponse {

        log.info { "CredentialRequestDeferred: ${Json.encodeToString(credReq)}" }

        credReq as CredentialRequestDraft11
        requireNotNull(credReq.types) { "No types in CredentialRequest" }

        val authContext = ctx.getAuthContext()
        val issuerMetadata = authContext.assertAttachment(EBSI32_ISSUER_METADATA_ATTACHMENT_KEY)
        val authRequest = authContext.assertAttachment(EBSI32_AUTHORIZATION_REQUEST_DRAFT11_ATTACHMENT_KEY)
        val supportedCredentials = issuerMetadata.credentialsSupported.flatMap { it.types.orEmpty() }.toSet()
        val unknownTypes = credReq.types!!.filterNot { it in supportedCredentials }
        if (unknownTypes.isNotEmpty()) throw IllegalStateException("Unknown credential types: $unknownTypes")


        val jti = "vc:nessus#${Uuid.random()}"
        val sub = authRequest.clientId
        val nbf = Instant.now().plusSeconds(5)

        val kid = ctx.didInfo.authenticationId()
        val acceptanceHeader = JWSHeader.Builder(JWSAlgorithm.ES256).type(JOSEObjectType.JWT).keyID(kid).build()

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

        val credResObj = WaltIdCredentialResponse.deferred(CredentialFormat.jwt_vc, acceptanceTokenJwt.serialize()).toJSON()
        val credResponse = CredentialResponse.fromJson(credResObj)
        log.info { "CredentialResponseDeferred: ${credResponse.toJson()}" }

        return credResponse
    }

    private suspend fun getCredentialFromParameters(
        ctx: LoginContext, vcp: CredentialParameters
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
        if (vcp.types.isEmpty()) throw java.lang.IllegalStateException("No types")

        // Verify credential types i.e. every type must bve known to this issuer
        val authContext = ctx.getAuthContext()
        val issuerMetadata = authContext.assertAttachment(EBSI32_ISSUER_METADATA_ATTACHMENT_KEY)
        val supportedCredentials = issuerMetadata.credentialsSupported.flatMap { it.types.orEmpty() }.toSet()
        val unknownTypes = vcp.types.filterNot { it in supportedCredentials }
        if (unknownTypes.isNotEmpty()) throw IllegalStateException("Unknown credential types: $unknownTypes")

        val cred =
            VCDataV11JwtBuilder().withId(id).withIssuerId(ctx.did).withSubjectId(vcp.sub as String).withIssuedAt(iat)
                .withValidFrom(nbf).withValidUntil(exp).withCredential(
                    W3CCredentialV11Builder().withCredentialSchema(
                            CredentialSchema(
                                "https://api-conformance.ebsi.eu/trusted-schemas-registry/v3/schemas/zDpWGUBenmqXzurskry9Nsk6vq2R8thh9VSeoRqguoyMD",
                                "FullJsonSchemaValidator2021"
                            )
                        ).withId(id).withIssuer(iss).withCredentialStatus(vcp.status).withCredentialSubject(sub)
                        .withIssuedAt(iat).withValidFrom(nbf).withValidUntil(exp).withTypes(vcp.types).build()
                ).build()

        val kid = ctx.didInfo.authenticationId()
        val credHeader = JWSHeader.Builder(JWSAlgorithm.ES256).type(JOSEObjectType.JWT).keyID(kid).build()

        val credJson = Json.encodeToString(cred)
        val credClaims = JWTClaimsSet.parse(JSONObjectUtils.parse(credJson))

        val credJwt = SignedJWT(credHeader, credClaims).signWithKey(ctx, kid)
        log.info { "Credential Header: ${credJwt.header}" }
        log.info { "Credential Claims: ${credJwt.jwtClaimsSet}" }

        credJwt.verifyJwtSignature("Credential", ctx.didInfo)

        val credResObj = WaltIdCredentialResponse.success(CredentialFormat.jwt_vc, credJwt.serialize()).toJSON()
        val credResponse = CredentialResponse.fromJson(credResObj)
        log.info { "CredentialResponse: ${credResponse.toJson()}" }

        return credResponse
    }

    override fun getIssuerMetadataUrl(): String {
        return "$endpointUri/${adminContext.targetId}/.well-known/openid-credential-issuer"
    }

    override suspend fun getIssuerMetadata(): IssuerMetadataDraft11 {
        val issuerMetadata = buildIssuerMetadata(adminContext)

        return issuerMetadata
    }

    override fun createUser(
        firstName: String, lastName: String, email: String, username: String, password: String
    ): UserInfo {
        error("Not implemented")
    }

    override fun findUser(predicate: (UserInfo) -> Boolean): UserInfo? {
        error("Not implemented")
    }

    override fun findUserByEmail(email: String): UserInfo? {
        error("Not implemented")
    }

    override fun getUsers(): List<UserInfo> {
        error("Not implemented")
    }

    override fun deleteUser(userId: String) {
        error("Not implemented")
    }

    // Private ---------------------------------------------------------------------------------------------------------

    private fun buildIssuerMetadata(ctx: LoginContext): IssuerMetadataDraft11 {
        val issuerTargetUrl = "$endpointUri/${ctx.targetId}"
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
            authorizationServer = issuerTargetUrl,
            authorizationEndpoint = "$issuerTargetUrl/authorize",
            pushedAuthorizationRequestEndpoint = "$issuerTargetUrl/par",
            tokenEndpoint = "$issuerTargetUrl/token",
            credentialEndpoint = "$issuerTargetUrl/credential",
            batchCredentialEndpoint = "$issuerTargetUrl/batch_credential",
            deferredCredentialEndpoint = "$issuerTargetUrl/credential_deferred",
            jwksUri = "$issuerTargetUrl/jwks",
            grantTypesSupported = setOf(GrantType.authorization_code, GrantType.pre_authorized_code),
            requestUriParameterSupported = true,
            subjectTypesSupported = setOf(SubjectType.public),
            credentialIssuer = issuerTargetUrl,
            responseTypesSupported = setOf(
                "code", "vp_token", "id_token"
            ),
            idTokenSigningAlgValuesSupported = setOf("ES256"),
            codeChallengeMethodsSupported = listOf("S256"),
            credentialSupported = credentialSupported,
        )
        val metadata = IssuerMetadataDraft11.fromJson(waltDraft11.toJSONString())
        return metadata
    }
}