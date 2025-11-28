package io.nessus.identity.console

import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import id.walt.oid4vc.data.AuthorizationDetails
import id.walt.oid4vc.data.CredentialFormat
import id.walt.oid4vc.data.CredentialSupported
import id.walt.oid4vc.data.DisplayProperties
import id.walt.oid4vc.data.GrantType
import id.walt.oid4vc.data.OpenIDProviderMetadata
import id.walt.oid4vc.data.SubjectType
import io.github.oshai.kotlinlogging.KotlinLogging
import io.ktor.http.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import io.ktor.util.*
import io.nessus.identity.config.ConfigProvider.requireEbsiConfig
import io.nessus.identity.config.User
import io.nessus.identity.extend.signWithKey
import io.nessus.identity.extend.verifyJwtSignature
import io.nessus.identity.service.AuthorizationContext.Companion.ACCESS_TOKEN_ATTACHMENT_KEY
import io.nessus.identity.service.AuthorizationContext.Companion.EBSI32_AUTHORIZATION_REQUEST_DRAFT11_ATTACHMENT_KEY
import io.nessus.identity.service.AuthorizationService
import io.nessus.identity.service.CredentialOfferRegistry.hasCredentialOfferRecord
import io.nessus.identity.service.CredentialOfferRegistry.isEBSIPreAuthorizedType
import io.nessus.identity.service.CredentialOfferRegistry.putCredentialOfferRecord
import io.nessus.identity.service.CredentialOfferRegistry.removeCredentialOfferRecord
import io.nessus.identity.service.LoginContext
import io.nessus.identity.types.AuthorizationRequestDraft11
import io.nessus.identity.types.CredentialOffer
import io.nessus.identity.types.CredentialOfferDraft11
import io.nessus.identity.types.IssuerMetadataDraft11
import io.nessus.identity.types.TokenRequest
import io.nessus.identity.types.TokenResponse
import io.nessus.identity.waltid.publicKeyJwk
import kotlinx.serialization.json.*
import java.time.Instant
import java.util.*
import kotlin.uuid.Uuid

abstract class AuthHandler(val authorizationSvc: AuthorizationService) {

    val log = KotlinLogging.logger {}

    val jsonPretty = Json { prettyPrint = true }

    abstract val endpointUri: String

    abstract suspend fun createCredentialOffer(
        configId: String,
        clientId: String? = null,
        preAuthorized: Boolean = false,
        userPin: String? = null,
        targetUser: User? = null,
    ): CredentialOffer

    suspend fun handleJwksRequest(call: RoutingCall, ctx: LoginContext) {

        val keyJwk = ctx.didInfo.publicKeyJwk()
        val keys = mapOf("keys" to listOf(keyJwk))
        val payload = Json.encodeToString(keys)

        log.info { "Jwks $payload" }

        call.respondText(
            status = HttpStatusCode.OK,
            contentType = ContentType.Application.Json,
            text = payload
        )
    }

    suspend fun handleTokenRequest(call: RoutingCall, ctx: LoginContext) {

        val postParams = call.receiveParameters().toMap()
        log.info { "Token Request: ${call.request.uri}" }
        postParams.forEach { (k, lst) -> lst.forEach { v -> log.info { "  $k=$v" } } }

        val tokenRequest = TokenRequest.fromHttpParameters(postParams)
        val tokRes = when (tokenRequest) {
            is TokenRequest.AuthorizationCode -> {
                handleTokenRequestAuthCode(ctx, tokenRequest)
            }

            is TokenRequest.PreAuthorizedCode -> {
                handleTokenRequestPreAuthorized(ctx, tokenRequest)
            }

            else -> error("Unsupported grant_type: ${tokenRequest.grantType}")
        }

        call.respondText(
            status = HttpStatusCode.OK,
            contentType = ContentType.Application.Json,
            text = Json.encodeToString(tokRes)
        )
    }

    // Protected -------------------------------------------------------------------------------------------------------

    protected fun getIssuerMetadataDraft11(ctx: LoginContext): IssuerMetadataDraft11 {
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

    private suspend fun buildTokenResponse(ctx: LoginContext): TokenResponse {

        val keyJwk = ctx.didInfo.publicKeyJwk()
        val kid = keyJwk["kid"]?.jsonPrimitive?.content as String

        val iat = Instant.now()
        val expiresIn: Long = 86400
        val exp = iat.plusSeconds(expiresIn)

        val nonce = "${Uuid.random()}"

        val issuerMetadata = getIssuerMetadataDraft11(ctx)
        val tokenHeader = JWSHeader.Builder(JWSAlgorithm.ES256).type(JOSEObjectType.JWT).keyID(kid).build()

        val claimsBuilder = JWTClaimsSet.Builder().issuer(issuerMetadata.credentialIssuer).issueTime(Date.from(iat))
            .expirationTime(Date.from(exp)).claim("nonce", nonce)

        val authContext = ctx.getAuthContext()
        val maybeAuthRequest = authContext.getAttachment(EBSI32_AUTHORIZATION_REQUEST_DRAFT11_ATTACHMENT_KEY)
        maybeAuthRequest?.clientId?.also {
            claimsBuilder.subject(it)
        }
        maybeAuthRequest?.authorizationDetails?.also {
            val authorizationDetails: List<JsonObject> = it.map { ad -> ad.toJSON() }
            claimsBuilder.claim("authorization_details", authorizationDetails)
        }
        val tokenClaims = claimsBuilder.build()

        val accessTokenJwt = SignedJWT(tokenHeader, tokenClaims).signWithKey(ctx, kid)
        log.info { "Token Header: ${accessTokenJwt.header}" }
        log.info { "Token Claims: ${accessTokenJwt.jwtClaimsSet}" }

        accessTokenJwt.verifyJwtSignature("AccessToken", ctx.didInfo)

        val tokenRespJson = """
            {
              "access_token": "${accessTokenJwt.serialize()}",
              "token_type": "bearer",
              "expires_in": $expiresIn,
              "c_nonce": "$nonce",
              "c_nonce_expires_in": $expiresIn
            }            
        """.trimIndent()

        log.info { "Token Response: $tokenRespJson" }
        val tokenRes = TokenResponse.fromJson(tokenRespJson).also {
            ctx.putAttachment(ACCESS_TOKEN_ATTACHMENT_KEY, accessTokenJwt)
        }
        return tokenRes
    }

    private suspend fun handleTokenRequestAuthCode(ctx: LoginContext, tokenReq: TokenRequest): TokenResponse {

        val tokReq = tokenReq as TokenRequest.AuthorizationCode
        val grantType = tokReq.grantType
        val codeVerifier = tokReq.codeVerifier
        val redirectUri = tokReq.redirectUri
        val code = tokReq.code

        // Verify token request
        //
        val authContext = ctx.getAuthContext()
        val authRequest = authContext.assertAttachment(EBSI32_AUTHORIZATION_REQUEST_DRAFT11_ATTACHMENT_KEY)
        require(tokReq.clientId == authRequest.clientId) { "Invalid client_id: ${tokReq.clientId}" }

        // [TODO #230] Verify token request code challenge
        // https://github.com/tdiesler/nessus-identity/issues/230

        val tokenRes = buildTokenResponse(ctx)
        return tokenRes
    }

    private suspend fun handleTokenRequestPreAuthorized(ctx: LoginContext, tokenReq: TokenRequest): TokenResponse {

        var clientId = tokenReq.clientId
        val preAuthTokenRequest = tokenReq as TokenRequest.PreAuthorizedCode
        val preAuthCode = preAuthTokenRequest.preAuthorizedCode
        val userPin = preAuthTokenRequest.userPin

        // In the EBSI Issuer Conformance Test, the preAuthCode is a known Credential type
        // and the clientId associated with the TokenRequest is undefined
        if (isEBSIPreAuthorizedType(preAuthCode)) {

            if (clientId == null) {
                val ebsiConfig = requireEbsiConfig()
                clientId = ebsiConfig.requesterDid as String
            }

            // Issuing CredentialOffers (on-demand) for EBSI Conformance
            if (!hasCredentialOfferRecord(preAuthCode)) {
                log.info { "Issuing CredentialOffer $preAuthCode (on-demand) for EBSI Conformance" }
                val credOffer = createCredentialOffer(preAuthCode, clientId, preAuthorized = true, userPin = userPin)
                putCredentialOfferRecord(preAuthCode, credOffer, userPin)
            }
        }

        // Verify pre-authorized user PIN
        //
        val credOfferRecord = removeCredentialOfferRecord(preAuthCode)
            ?: throw IllegalStateException("No CredentialOffer registered")
        val expUserPin = credOfferRecord.userPin
            ?: throw IllegalStateException("No UserPin")

        if (userPin != expUserPin)
            throw IllegalStateException("Invalid UserPin")

        val credOffer = credOfferRecord.credOffer as CredentialOfferDraft11
        val types = credOffer.credentialConfigurationIds
        val authRequest = AuthorizationRequestDraft11(
            clientId = clientId ?: throw IllegalStateException("No subId"),
            authorizationDetails = listOf(
                AuthorizationDetails(
                    format = CredentialFormat.jwt_vc,
                    types = types
                )
            )
        )

        val authContext = ctx.getAuthContext()
        authContext.putAttachment(EBSI32_AUTHORIZATION_REQUEST_DRAFT11_ATTACHMENT_KEY, authRequest)

        val tokenResponse = buildTokenResponse(ctx)
        return tokenResponse
    }

}
