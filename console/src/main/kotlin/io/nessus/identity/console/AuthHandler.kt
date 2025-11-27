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
import io.ktor.client.request.*
import io.ktor.client.statement.*
import io.ktor.http.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import io.ktor.util.*
import io.nessus.identity.config.ConfigProvider.requireEbsiConfig
import io.nessus.identity.extend.signWithKey
import io.nessus.identity.extend.verifyJwtSignature
import io.nessus.identity.service.AuthorizationContext
import io.nessus.identity.service.AuthorizationContext.Companion.EBSI32_ACCESS_TOKEN_ATTACHMENT_KEY
import io.nessus.identity.service.AuthorizationContext.Companion.EBSI32_AUTHORIZATION_REQUEST_ATTACHMENT_KEY
import io.nessus.identity.service.AuthorizationContext.Companion.EBSI32_AUTH_CODE_ATTACHMENT_KEY
import io.nessus.identity.service.CredentialOfferRegistry.hasCredentialOfferRecord
import io.nessus.identity.service.CredentialOfferRegistry.isEBSIPreAuthorizedType
import io.nessus.identity.service.CredentialOfferRegistry.putCredentialOfferRecord
import io.nessus.identity.service.CredentialOfferRegistry.removeCredentialOfferRecord
import io.nessus.identity.service.HttpStatusException
import io.nessus.identity.service.LoginContext
import io.nessus.identity.service.LoginContext.Companion.AUTH_CONTEXT_ATTACHMENT_KEY
import io.nessus.identity.service.WalletAuthorizationService
import io.nessus.identity.service.WalletService
import io.nessus.identity.service.http
import io.nessus.identity.service.urlQueryToMap
import io.nessus.identity.types.AuthorizationCodeGrant
import io.nessus.identity.types.AuthorizationRequestDraft11
import io.nessus.identity.types.CredentialObject
import io.nessus.identity.types.CredentialOfferDraft11
import io.nessus.identity.types.Grants
import io.nessus.identity.types.IssuerMetadataDraft11
import io.nessus.identity.types.PreAuthorizedCodeGrant
import io.nessus.identity.types.TokenRequest
import io.nessus.identity.types.TokenResponse
import io.nessus.identity.waltid.authenticationId
import io.nessus.identity.waltid.publicKeyJwk
import kotlinx.serialization.json.*
import java.time.Instant
import java.util.*
import kotlin.uuid.Uuid

abstract class AuthHandler {

    val log = KotlinLogging.logger {}

    val jsonPretty = Json { prettyPrint = true }

    val walletSvc: WalletService = WalletService.create()
    val walletAuthSvc = WalletAuthorizationService(walletSvc)

    abstract val endpointUri: String

    fun buildAuthCodeRedirectUri(ctx: LoginContext, authCode: String): String {

        val authContext = ctx.assertAttachment(AUTH_CONTEXT_ATTACHMENT_KEY)
        val authReq = authContext.assertAttachment(EBSI32_AUTHORIZATION_REQUEST_ATTACHMENT_KEY)
        val authCodeRedirect = URLBuilder("${authReq.redirectUri}").apply {
            parameters.append("code", authCode)
            authReq.state?.also { state ->
                parameters.append("state", state)
            }
        }.buildString()

        log.info { "AuthCode Redirect: $authCodeRedirect" }
        urlQueryToMap(authCodeRedirect).also {
            it.forEach { (k, v) -> log.info { "  $k=$v" } }
        }

        return authCodeRedirect
    }

    suspend fun buildIDTokenRequest(ctx: LoginContext, authReq: AuthorizationRequestDraft11): SignedJWT {

        val requesterDid = requireEbsiConfig().requesterDid
        val targetEndpointUri = "$endpointUri/${ctx.targetId}"

        val keyJwk = ctx.didInfo.publicKeyJwk()
        val kid = keyJwk["kid"]?.jsonPrimitive?.content as String

        val iat = Instant.now()
        val exp = iat.plusSeconds(300) // 5 mins expiry

        val idTokenHeader = JWSHeader.Builder(JWSAlgorithm.ES256).type(JOSEObjectType.JWT).keyID(kid).build()

        val idTokenClaims =
            JWTClaimsSet.Builder().issuer(requesterDid).audience(authReq.clientId)
                .issueTime(Date.from(iat)).expirationTime(Date.from(exp)).claim("response_type", "id_token")
                .claim("response_mode", "direct_post")
                .claim("client_id", requesterDid)
                .claim("redirect_uri", "$targetEndpointUri/direct_post")
                .claim("scope", "openid")
                .claim("nonce", "${Uuid.random()}").build()

        val idTokenJwt = SignedJWT(idTokenHeader, idTokenClaims).signWithKey(ctx, kid)
        log.info { "IDToken Request Header: ${idTokenJwt.header}" }
        log.info { "IDToken Request Claims: ${idTokenJwt.jwtClaimsSet}" }

        return idTokenJwt
    }

    fun buildIDTokenRedirectUrl(redirectUri: String, idTokenReqJwt: SignedJWT): String {

        val claims = idTokenReqJwt.jwtClaimsSet
        val idTokenRedirectUrl = URLBuilder(redirectUri).apply {
            for (k in listOf("client_id", "nonce", "scope", "redirect_uri", "response_mode", "response_type")) {
                val v = claims.getClaim(k) as String
                parameters.append(k, v)
            }
            parameters.append("request", "${idTokenReqJwt.serialize()}")
        }.buildString()

        log.info { "IDToken Redirect $idTokenRedirectUrl" }
        urlQueryToMap(idTokenRedirectUrl).also {
            it.forEach { (k, v) -> log.info { "  $k=$v" } }
        }

        return idTokenRedirectUrl
    }

    suspend fun handleIDTokenRequest(call: RoutingCall, ctx: LoginContext) {

        val authContext = ctx.assertAttachment(AUTH_CONTEXT_ATTACHMENT_KEY)

        val reqParams = urlQueryToMap(call.request.uri).toMutableMap()
        val redirectUri = reqParams["redirect_uri"] as String
        val requestUri = reqParams["request_uri"]

        // Replace IDToken request params with the response from request_uri
        if (requestUri != null) {
            log.info { "IDToken params from: $requestUri" }
            val res = http.get(requestUri)
            if (res.status != HttpStatusCode.OK)
                throw HttpStatusException(res.status, res.bodyAsText())
            val uriRes = res.bodyAsText()
            log.info { "UriResponse: $uriRes" }
            val resJwt = SignedJWT.parse(uriRes)
            log.info { "UriResponse Header: ${resJwt.header}" }
            log.info { "UriResponse Claims: ${resJwt.jwtClaimsSet}" }
            for ((k, v) in resJwt.jwtClaimsSet.claims) {
                reqParams[k] = "$v"
            }
        } else {
            reqParams["response_type"] = "id_token"
        }

        val idTokenJwt = walletAuthSvc.createIDToken(ctx, reqParams)
        walletAuthSvc.sendIDToken(authContext, redirectUri, idTokenJwt)

        call.respondText(
            status = HttpStatusCode.Accepted,
            contentType = ContentType.Text.Plain,
            text = "Accepted"
        )
    }

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

        val tokenReq = TokenRequest.fromHttpParameters(postParams)
        val tokRes = when (tokenReq) {
            is TokenRequest.AuthorizationCode -> {
                handleTokenRequestAuthCode(ctx, tokenReq)
            }

            is TokenRequest.PreAuthorizedCode -> {
                handleTokenRequestPreAuthorized(ctx, tokenReq)
            }

            else -> error("Unsupported grant_type: ${tokenReq.grantType}")
        }

        call.respondText(
            status = HttpStatusCode.OK,
            contentType = ContentType.Application.Json,
            text = Json.encodeToString(tokRes)
        )
    }

    fun validateIDToken(ctx: LoginContext, idTokenJwt: SignedJWT): String {

        log.info { "IDToken Header: ${idTokenJwt.header}" }
        log.info { "IDToken Claims: ${idTokenJwt.jwtClaimsSet}" }

        // [TODO #233] Verify IDToken proof DID ownership
        // https://github.com/tdiesler/nessus-identity/issues/233
        // We should be able to use the Holder's public key to do that

        val authCode = "${Uuid.random()}"
        val authContext = ctx.assertAttachment(AUTH_CONTEXT_ATTACHMENT_KEY)
        authContext.putAttachment(EBSI32_AUTH_CODE_ATTACHMENT_KEY, authCode)

        val authReq = authContext.assertAttachment(EBSI32_AUTHORIZATION_REQUEST_ATTACHMENT_KEY)
        val idTokenRedirect = URLBuilder("${authReq.redirectUri}").apply {
            parameters.append("code", authCode)
            authReq.state?.also { state ->
                parameters.append("state", state)
            }
        }.buildString()

        log.info { "IDToken Response $idTokenRedirect" }
        urlQueryToMap(idTokenRedirect).also {
            it.forEach { (k, v) -> log.info { "  $k=$v" } }
        }

        return idTokenRedirect
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

        val authContext = ctx.getAttachment(AUTH_CONTEXT_ATTACHMENT_KEY)
        val maybeAuthRequest = authContext?.getAttachment(EBSI32_AUTHORIZATION_REQUEST_ATTACHMENT_KEY)
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
            ctx.putAttachment(EBSI32_ACCESS_TOKEN_ATTACHMENT_KEY, accessTokenJwt)
        }
        return tokenRes
    }

    private suspend fun createCredentialOfferDraft11(
        ctx: LoginContext,
        subjectId: String,
        types: List<String>,
        userPin: String? = null
    ): CredentialOfferDraft11 {

        val metadata = getIssuerMetadataDraft11(ctx)
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

    private suspend fun handleTokenRequestAuthCode(ctx: LoginContext, tokenReq: TokenRequest): TokenResponse {

        val tokReq = tokenReq as TokenRequest.AuthorizationCode
        val grantType = tokReq.grantType
        val codeVerifier = tokReq.codeVerifier
        val redirectUri = tokReq.redirectUri
        val code = tokReq.code

        // Verify token request
        //
        val authContext = ctx.assertAttachment(AUTH_CONTEXT_ATTACHMENT_KEY)
        val authRequest = authContext.assertAttachment(EBSI32_AUTHORIZATION_REQUEST_ATTACHMENT_KEY)
        require (tokReq.clientId == authRequest.clientId) { "Invalid client_id: ${tokReq.clientId}" }

        // [TODO #230] Verify token request code challenge
        // https://github.com/tdiesler/nessus-identity/issues/230

        val tokenRes = buildTokenResponse(ctx)
        return tokenRes
    }

    private suspend fun handleTokenRequestPreAuthorized(ctx: LoginContext, tokenReq: TokenRequest): TokenResponse {

        var subId = tokenReq.clientId
        val preAuthTokenRequest = tokenReq as TokenRequest.PreAuthorizedCode
        val preAuthCode = preAuthTokenRequest.preAuthorizedCode
        val userPin = preAuthTokenRequest.userPin

        // In the EBSI Issuer Conformance Test, the preAuthCode is a known Credential type
        // and the clientId associated with the TokenRequest is undefined
        if (isEBSIPreAuthorizedType(preAuthCode)) {

            if (subId == null) {
                val ebsiConfig = requireEbsiConfig()
                subId = ebsiConfig.requesterDid as String
            }

            // Issuing CredentialOffers (on-demand) for EBSI Conformance
            if (!hasCredentialOfferRecord(preAuthCode)) {
                log.info { "Issuing CredentialOffer $preAuthCode (on-demand) for EBSI Conformance" }
                val types = listOf("VerifiableCredential", preAuthCode)
                val credOffer = createCredentialOfferDraft11(ctx, subId, types, userPin)
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
            clientId = subId ?: throw IllegalStateException("No subId"), authorizationDetails = listOf(
                AuthorizationDetails(
                    format = CredentialFormat.jwt_vc, types = types
                )
            )
        )

        // Create an AuthorizationContext on demand
        val authContext = ctx.getAttachment(AUTH_CONTEXT_ATTACHMENT_KEY) ?: AuthorizationContext.create(ctx)
        authContext.putAttachment(EBSI32_AUTHORIZATION_REQUEST_ATTACHMENT_KEY, authRequest)

        val tokenResponse = buildTokenResponse(ctx)
        return tokenResponse
    }

}
