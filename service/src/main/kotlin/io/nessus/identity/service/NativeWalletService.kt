package io.nessus.identity.service

import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.JWSObject
import com.nimbusds.jose.crypto.ECDSAVerifier
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.util.Base64URL
import com.nimbusds.jose.util.JSONObjectUtils
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import id.walt.oid4vc.data.CredentialFormat
import id.walt.oid4vc.data.dif.DescriptorMapping
import id.walt.oid4vc.data.dif.PresentationSubmission
import id.walt.w3c.utils.VCFormat
import id.walt.webwallet.db.models.WalletCredential
import io.github.oshai.kotlinlogging.KotlinLogging
import io.ktor.client.*
import io.ktor.client.plugins.contentnegotiation.*
import io.ktor.client.request.*
import io.ktor.client.statement.*
import io.ktor.http.*
import io.ktor.serialization.kotlinx.json.*
import io.nessus.identity.AuthorizationContext
import io.nessus.identity.AuthorizationContext.Companion.AUTHORIZATION_CODE_ATTACHMENT_KEY
import io.nessus.identity.AuthorizationContext.Companion.CODE_VERIFIER_ATTACHMENT_KEY
import io.nessus.identity.AuthorizationContext.Companion.EBSI32_AUTHORIZATION_REQUEST_DRAFT11_ATTACHMENT_KEY
import io.nessus.identity.AuthorizationContext.Companion.EBSI32_REQUEST_URI_OBJECT_ATTACHMENT_KEY
import io.nessus.identity.AuthorizationContext.Companion.USER_PIN_ATTACHMENT_KEY
import io.nessus.identity.LoginContext
import io.nessus.identity.LoginContext.Companion.USER_ATTACHMENT_KEY
import io.nessus.identity.OAuthClient
import io.nessus.identity.OAuthClient.Companion.handleApiResponse
import io.nessus.identity.config.ConfigProvider.requireEbsiConfig
import io.nessus.identity.config.ConfigProvider.requireIssuerConfig
import io.nessus.identity.config.WalletConfig
import io.nessus.identity.service.IssuerService.Companion.KNOWN_ISSUER_EBSI_V3
import io.nessus.identity.types.AuthorizationRequest
import io.nessus.identity.types.AuthorizationRequestBuilder
import io.nessus.identity.types.AuthorizationRequestDraft11
import io.nessus.identity.types.AuthorizationRequestDraft11Builder
import io.nessus.identity.types.AuthorizationRequestV0
import io.nessus.identity.types.CredentialMatcherV10
import io.nessus.identity.types.CredentialOffer
import io.nessus.identity.types.CredentialOfferDraft11
import io.nessus.identity.types.CredentialOfferV0
import io.nessus.identity.types.CredentialRequest
import io.nessus.identity.types.CredentialRequestDraft11
import io.nessus.identity.types.CredentialRequestV0
import io.nessus.identity.types.CredentialResponse
import io.nessus.identity.types.CredentialResponseDraft11
import io.nessus.identity.types.CredentialResponseV0
import io.nessus.identity.types.DCQLQuery
import io.nessus.identity.types.IssuerMetadataDraft11
import io.nessus.identity.types.IssuerMetadataV0
import io.nessus.identity.types.QueryClaim
import io.nessus.identity.types.SubmissionBundle
import io.nessus.identity.types.TokenRequest
import io.nessus.identity.types.TokenResponse
import io.nessus.identity.types.W3CCredentialJwt
import io.nessus.identity.types.W3CCredentialSdV11Jwt
import io.nessus.identity.types.W3CCredentialV11Jwt
import io.nessus.identity.types.authenticationId
import io.nessus.identity.utils.HttpStatusException
import io.nessus.identity.utils.base64UrlEncode
import io.nessus.identity.utils.http
import io.nessus.identity.utils.signWithKey
import io.nessus.identity.utils.urlQueryToMap
import io.nessus.identity.utils.verifyJwtSignature
import io.nessus.identity.waltid.WaltIDServiceProvider
import io.nessus.identity.waltid.WaltIDServiceProvider.widWalletService
import kotlinx.coroutines.delay
import kotlinx.serialization.json.*
import java.time.Instant
import java.util.*
import kotlin.random.Random
import kotlin.time.Clock
import kotlin.time.Duration.Companion.minutes
import kotlin.uuid.Uuid

// NativeWalletService =================================================================================================

class NativeWalletService(val config: WalletConfig): AbstractWalletService() {

    val log = KotlinLogging.logger {}

    override val endpointUri = config.baseUrl
    override val defaultClientId = requireIssuerConfig().clientId ?: ""
    override val authorizationSvc = NativeAuthorizationService(endpointUri)

    // ExperimentalWalletService ---------------------------------------------------------------------------------------

    override suspend fun createIDToken(
        ctx: LoginContext,
        authRequest: AuthorizationRequest
    ): SignedJWT {
        val idTokenJwt = authorizationSvc.createIDToken(ctx, authRequest)
        return idTokenJwt
    }


    override suspend fun authorizeFromCredentialOffer(
        ctx: LoginContext,
        credOffer: CredentialOffer,
        clientId: String,
    ): TokenResponse {

        val authContext = ctx.getAuthContext().withCredentialOffer(credOffer)
        val issuerMetadata = authContext.getIssuerMetadata()

        if (credOffer.isPreAuthorized) {
            val authMetadata = authContext.getAuthorizationMetadata()
            val preAuthorizedCodeGrant = credOffer.getPreAuthorizedCodeGrant()!!
            val code = preAuthorizedCodeGrant.preAuthorizedCode
            val tokenEndpointUrl = authMetadata.getAuthorizationTokenEndpointUri()
            var userPin = authContext.getAttachment(USER_PIN_ATTACHMENT_KEY)
            if (credOffer.isUserPinRequired && userPin == null) {
                userPin = requireEbsiConfig().preAuthUserPin
            }
            val tokReq = TokenRequest.PreAuthorizedCode(
                clientId = clientId,
                preAuthorizedCode = code,
                userPin = userPin
            )
            val tokenRes = OAuthClient().sendTokenRequest(tokenEndpointUrl, tokReq)
            log.info { "TokenResponse: ${tokenRes.toJson()}" }
            return tokenRes
        }

        if (credOffer is CredentialOfferDraft11) {
            val authRequest = buildAuthorizationRequestFromOffer(ctx, credOffer)
            val authEndpointUri = issuerMetadata.getAuthorizationMetadata().getAuthorizationEndpointUri()
            val authCode = sendAuthorizationRequest(ctx, authEndpointUri, authRequest)
            val tokenRes = getAccessTokenFromCode(ctx, authCode)
            return tokenRes
        }

        val holder = ctx.assertAttachment(USER_ATTACHMENT_KEY)
        val authCode = getAuthorizationCode(ctx,
            clientId = defaultClientId,
            username = holder.username,
            password = holder.password
        )
        val tokenRes = getAccessTokenFromCode(ctx, authCode)
        return tokenRes
    }

    override suspend fun authorizeWithDirectAccess(
        ctx: LoginContext,
        clientId: String
    ): TokenResponse {
        val authMetadata = authorizationSvc.getAuthorizationMetadata(ctx)
        val tokenEndpointUrl = authMetadata.getAuthorizationTokenEndpointUri()
        val scopes = mutableListOf("openid")

        val authContext = ctx.getAuthContext()
        authContext.credentialConfigurationIds?.also {
            scopes.addAll(it)
        }

        val loginContext = requireNotNull(authContext.loginContext) { "No login context " }
        val user = requireNotNull(loginContext.getAttachment(USER_ATTACHMENT_KEY)) { "No attached user " }

        val tokReq = TokenRequest.DirectAccess(
            clientId = clientId,
            username = user.username,
            password = user.password,
            scopes = scopes
        )

        val tokRes = OAuthClient().sendTokenRequest(tokenEndpointUrl, tokReq)
        log.info { "TokenResponse: ${tokRes.toJson()}" }
        return tokRes
    }

    override suspend fun getCredentialOfferFromUri(offerUri: String): CredentialOffer {
        val credOfferRes = http.get(offerUri)
        val credOffer = (handleApiResponse(credOfferRes) as CredentialOfferV0)
        log.info { "CredentialOffer: ${credOffer.toJson()}" }
        return credOffer
    }

    override suspend fun getCredential(
        ctx: LoginContext,
        accessToken: TokenResponse
    ): W3CCredentialJwt {
        val authContext = ctx.getAuthContext()
        val credConfigIds = authContext.credentialConfigurationIds
        val credResponse = sendCredentialRequest(authContext, accessToken, null, credConfigIds)

        // Validate the Credential
        //
        val signedJwt = extractCredentialFromResponse(credResponse)
        val (_, format) = validateCredential(ctx, signedJwt)

        // Store the Credential
        //
        storeCredential(ctx, format, signedJwt)

        val credJwt = W3CCredentialJwt.fromEncoded("${signedJwt.serialize()}")
        return credJwt
    }

    override suspend fun getCredentialFromOffer(ctx: LoginContext, credOffer: CredentialOffer): W3CCredentialJwt {

        val authContext = ctx.getAuthContext().withCredentialOffer(credOffer)

        val issuerMetadata = authContext.getIssuerMetadata()
        val clientId = when(credOffer) {
            is CredentialOfferDraft11 -> ctx.did
            else -> defaultClientId
        }
        val accessToken = authorizeFromCredentialOffer(ctx, credOffer, clientId)

        var cNonce = accessToken.cNonce
        if (cNonce == null && issuerMetadata is IssuerMetadataV0) {
            val res = http.post(issuerMetadata.nonceEndpoint!!)
            if (res.status != HttpStatusCode.OK)
                throw HttpStatusException(res.status, res.bodyAsText())
            val jsonObj = Json.decodeFromString<JsonObject>(res.bodyAsText())
            cNonce = jsonObj.getValue("c_nonce").jsonPrimitive.content
        }

        val credConfigIds = credOffer.credentialConfigurationIds
        val credRequest = buildCredentialRequest(authContext, cNonce, null, credConfigIds)

        val res = http.post(issuerMetadata.credentialEndpoint) {
            header(HttpHeaders.Authorization, "Bearer ${accessToken.accessToken}")
            contentType(ContentType.Application.Json)
            setBody(credRequest.toJson())
        }
        val credResJson = res.bodyAsText()
        if (res.status != HttpStatusCode.OK)
            throw HttpStatusException(res.status, credResJson)

        log.info { "CredentialResponse: $credResJson" }
        var credResponse = CredentialResponse.fromJson(credResJson)

        var numRetry = 0
        val maxRetries = 10
        while (credResponse is CredentialResponseDraft11 && credResponse.acceptanceToken != null && numRetry < maxRetries) {
            delay(5500)

            val deferredCredentialEndpoint =
                issuerMetadata.deferredCredentialEndpoint ?: error("No credential_endpoint")
            log.info { "${++numRetry}/$maxRetries fetching deferred credential from: $deferredCredentialEndpoint" }

            val res = http.post(deferredCredentialEndpoint) {
                header(HttpHeaders.Authorization, "Bearer ${credResponse.acceptanceToken}")
            }
            val credResJson = res.bodyAsText()
            if (res.status != HttpStatusCode.OK)
                throw HttpStatusException(res.status, credResJson)

            log.info { "CredentialResponse: $credResJson" }
            credResponse = CredentialResponse.fromJson(credResJson)
        }

        // Validate the Credential
        //
        val signedJwt = extractCredentialFromResponse(credResponse)
        val (_, format) = validateCredential(ctx, signedJwt)

        // Store the Credential
        //
        storeCredential(ctx, format, signedJwt)

        val credJwt = W3CCredentialJwt.fromEncoded("${signedJwt.serialize()}")
        return credJwt
    }

    override suspend fun buildAuthorizationRequestFromOffer(
        ctx: LoginContext,
        credOffer: CredentialOffer
    ): AuthorizationRequestDraft11 {

        val authContext = ctx.getAuthContext().withCredentialOffer(credOffer)
        val issuerMetadata = authContext.getIssuerMetadata()

        val rndBytes = Random.nextBytes(32)
        val codeVerifier = Base64URL.encode(rndBytes).toString()
        val redirectUri = "${endpointUri}/${ctx.targetId}/authorize"
        val authRequest = when (issuerMetadata) {
            is IssuerMetadataV0 -> {
                error("[TODO] Not implemented")
            }

            is IssuerMetadataDraft11 -> {
                AuthorizationRequestDraft11Builder()
                    .withClientId(ctx.did)
                    .withClientState(ctx.walletId)
                    .withCodeChallengeMethod("S256")
                    .withCodeVerifier(codeVerifier)
                    .withIssuerMetadata(issuerMetadata)
                    .withRedirectUri(redirectUri)
                    .buildFrom(credOffer as CredentialOfferDraft11)
            }
        }
        authContext.putAttachment(CODE_VERIFIER_ATTACHMENT_KEY, codeVerifier)
        authContext.putAttachment(EBSI32_AUTHORIZATION_REQUEST_DRAFT11_ATTACHMENT_KEY, authRequest)
        return authRequest
    }

    override suspend fun buildCredentialRequest(
        ctx: LoginContext,
        authRequest: AuthorizationRequest
    ): CredentialRequest {
        val authContext = ctx.getAuthContext()
        val issuerMetadata = authContext.getIssuerMetadata()
        val credentialIssuer = issuerMetadata.credentialIssuer

        val iat = Instant.now()
        val exp = iat.plusSeconds(300) // 5 mins expiry

        val kid = ctx.didInfo.authenticationId()
        val proofHeader = JWSHeader.Builder(JWSAlgorithm.ES256)
            .type(JOSEObjectType("openid4vci-proof+jwt"))
            .keyID(kid)
            .build()
        val proofClaimsBuilder = JWTClaimsSet.Builder()
            .issuer(ctx.did)
            .audience(credentialIssuer)
            .issueTime(Date.from(iat))
            .expirationTime(Date.from(exp))
        //.claim("nonce", cNonce)

        authRequest.state?.also { proofClaimsBuilder.claim("state", it) }

        val proofClaims = proofClaimsBuilder.build()
        val proofJwt = SignedJWT(proofHeader, proofClaims).signWithKey(ctx, kid)

        log.info { "ProofHeader: ${proofJwt.header}" }
        log.info { "ProofClaims: ${proofJwt.jwtClaimsSet}" }

        val credRequest = when(authRequest) {
            is AuthorizationRequestDraft11 -> {
                val authorizationDetails = authRequest.authorizationDetails
                require(authorizationDetails?.isNotEmpty() ?: false) { "No authorization_details" }
                require(authorizationDetails.size == 1) { "Multiple authorization_details" }

                val types = authorizationDetails[0].types
                val format = requireNotNull(authorizationDetails[0].format?.value) { "No authorization_details.format" }
                CredentialRequestDraft11(
                    format = format,
                    types = types,
                    proof = CredentialRequestDraft11.Proof(
                        proofType = "jwt",
                        jwt = proofJwt.serialize()
                    )
                )
            }
            else -> error("Unsupported AuthorizationRequest: ${authRequest.toJson()}")
        }

        log.info { "CredentialRequest: ${credRequest.toJson()}" }
        return credRequest
    }

    override suspend fun getTokenRequestFromAuthorizationCode(
        ctx: LoginContext,
        authCode: String
    ): TokenRequest {
        val authContext = ctx.getAuthContext()
        val authRequestDraft11 = authContext.getAttachment(EBSI32_AUTHORIZATION_REQUEST_DRAFT11_ATTACHMENT_KEY)
        val tokenRequest = when {
            authRequestDraft11 != null -> {
                val codeVerifier = authContext.assertAttachment(CODE_VERIFIER_ATTACHMENT_KEY)
                TokenRequest.AuthorizationCode(
                    clientId = authRequestDraft11.clientId,
                    redirectUri = authRequestDraft11.redirectUri,
                    codeVerifier = codeVerifier,
                    code = authCode
                )
            }

            else -> {
                val authRequest = authContext.authRequest
                TokenRequest.AuthorizationCode(
                    clientId = authRequest.clientId,
                    redirectUri = authRequest.redirectUri,
                    codeVerifier = authContext.codeVerifier,
                    code = authCode
                )
            }
        }
        return tokenRequest
    }

    override suspend fun getAccessTokenFromCode(
        ctx: LoginContext,
        authCode: String,
    ): TokenResponse {
        val tokenRequest = getTokenRequestFromAuthorizationCode(ctx, authCode)
        val tokenResponse = sendTokenRequest(ctx, tokenRequest)
        return tokenResponse
    }

    override suspend fun sendAuthorizationRequest(
        ctx: LoginContext,
        authEndpointUri: String,
        authRequest: AuthorizationRequest,
    ): String {

        val authReqUrl = URLBuilder(authEndpointUri).apply {
            authRequest.toRequestParameters().forEach { (k, lst) -> lst.forEach { v -> parameters.append(k, v) } }
        }.buildString()

        log.info { "Send AuthorizationRequest: $authReqUrl" }
        authRequest.toRequestParameters().forEach { (k, lst) -> lst.forEach { v -> log.info { "  $k=$v" } } }

        // Disable follow redirects
        //
        val http = HttpClient {
            install(ContentNegotiation) {
                json()
            }
            followRedirects = false
            // install(Logging) {
            //     logger = Logger.DEFAULT
            //     level = LogLevel.ALL
            // }
        }

        var res = http.get(authReqUrl)

        val authContext = ctx.getAuthContext()
        if (res.status == HttpStatusCode.Found) {

            log.error { "Redirect response: ${res.status}" }
            res.headers.forEach { k, lst -> lst.forEach { v -> log.debug { "  $k: $v" } } }

            // First try access the location as given
            val locationUri = res.headers["location"] as String
            res = http.get(locationUri)


            // Cloudflare may reject the request because of url size limits or other WAF rules
            // We try again using 'request_uri' syntax with an in-memory request object
            // https://openid.net/specs/openid-connect-core-1_0.html#UseRequestUri
            if (res.status == HttpStatusCode.BadRequest) {
                log.warn { "Direct redirect [length=${locationUri.length}] failed with: ${res.status}" }
                val urlBase = locationUri.substringBefore('?')
                val queryParams = urlQueryToMap(locationUri)
                if (queryParams["request"] != null) {

                    // Redirect location is expected to be an Authorization Request
                    val authReq = AuthorizationRequestDraft11.fromHttpParameters(queryParams)

                    // Store the AuthorizationRequest in memory
                    val reqObjectId = "${Uuid.random()}"
                    authContext.putAttachment(EBSI32_REQUEST_URI_OBJECT_ATTACHMENT_KEY, authReq)

                    log.info { "Converting 'request' to 'request_uri'" }

                    // Values for the response_type and client_id parameters MUST be included using the OAuth 2.0 request syntax.
                    val urlString = URLBuilder(urlBase).apply {
                        parameters.append("client_id", queryParams["client_id"] as String)
                        parameters.append("request_uri", "$urlBase?request_object=$reqObjectId")
                        parameters.append("response_type", queryParams["response_type"] as String)
                    }.buildString()
                    res = http.get(urlString)
                }
            }
        }

        if (res.status != HttpStatusCode.Accepted) {
            log.error { "Unexpected response status: ${res.status}" }
            res.headers.forEach { k, lst -> lst.forEach { v -> log.warn { "  $k: $v" } } }
            throw HttpStatusException(res.status, res.bodyAsText())
        }

        val authCode = authContext.assertAttachment(AUTHORIZATION_CODE_ATTACHMENT_KEY)
        log.info { "AuthorizationCode: $authCode" }
        return authCode
    }

    override suspend fun sendTokenRequest(
        ctx: LoginContext,
        tokenRequest: TokenRequest
    ): TokenResponse {
        val authContext = ctx.getAuthContext()
        val authMetadata = authContext.getAuthorizationMetadata()
        val tokenEndpointUrl = authMetadata.getAuthorizationTokenEndpointUri()
        val tokenResponse = OAuthClient().sendTokenRequest(tokenEndpointUrl, tokenRequest)
        log.info { "TokenResponse: ${tokenResponse.toJson()}" }
        return tokenResponse
    }

    // LegacyWalletService ---------------------------------------------------------------------------------------------

    @Deprecated("promote or remove")
    override suspend fun buildAuthorizationRequest(
        authContext: AuthorizationContext,
        clientId: String,
        redirectUri: String
    ): AuthorizationRequestV0 {
        val rndBytes = Random.nextBytes(32)
        val codeVerifier = Base64URL.encode(rndBytes).toString()
        authContext.withCodeVerifier(codeVerifier)

        val authRequest = if (authContext.credOffer != null) {
            val credOffer = authContext.credOffer ?: error("No credential offer")
            buildAuthorizationRequestFromOffer(authContext, credOffer, clientId, redirectUri, codeVerifier)
        } else {
            val configIds = authContext.credentialConfigurationIds ?: error("No credential configuration ids")
            buildAuthorizationRequestFromConfigIds(
                authContext,
                configIds,
                clientId,
                redirectUri,
                codeVerifier
            )
        }
        authContext.withAuthorizationRequest(authRequest)
        return authRequest
    }

    @Deprecated("promote or remove")
    override suspend fun buildPresentationSubmission(
        ctx: LoginContext,
        dcql: DCQLQuery
    ): SubmissionBundle {
        val vcArray = mutableListOf<SignedJWT>()
        val descriptorMappings = mutableListOf<DescriptorMapping>()
        val queryIds = mutableListOf<String>()
        findMatchingCredentials(ctx, dcql).forEach { (wc, queryId, claims) ->
            val n = vcArray.size
            queryIds.add(queryId)
            val dm = DescriptorMapping(
                format = VCFormat.entries.first { it.value == wc.format.value },
                path = "$.vp.verifiableCredential[$n]",
            )
            val credJwt = W3CCredentialJwt.fromEncoded(wc.document)
            val sigJwt = when (credJwt) {
                is W3CCredentialV11Jwt -> SignedJWT.parse(wc.document)
                is W3CCredentialSdV11Jwt -> {
                    if (claims == null || claims.isEmpty()) {
                        SignedJWT.parse(wc.document)
                    } else {
                        val parts = mutableListOf(wc.document.substringBefore("~"))
                        val claimMap = credJwt.disclosures.associateBy { disc -> disc.claim }
                        val digests = claims.map { cl ->
                            require(cl.path.size == 1) { "Invalid path in: $cl" }
                            val encoded = claimMap[cl.path[0]]?.decoded ?: error("No digest for: $cl")
                            base64UrlEncode(encoded.toByteArray())
                        }
                        parts.addAll(digests)
                        SignedJWT.parse(parts.joinToString("~"))
                    }
                }
            }
            descriptorMappings.add(dm)
            vcArray.add(sigJwt)
        }

        // The presentation_submission object **MUST** contain a definition_id property.
        // The value of this property **MUST** be the id value of a valid Presentation Definition.
        // https://identity.foundation/presentation-exchange/#presentation-submission
        //
        // In the absence of a Presentation Definition
        val vpSubmission = PresentationSubmission(
            id = "${Uuid.random()}",
            definitionId = "dcql:${queryIds.joinToString("-")}",
            descriptorMap = descriptorMappings
        )
        return SubmissionBundle(vcArray, vpSubmission)
    }

    @Deprecated("promote or remove")
    override suspend fun getAuthorizationCode(
        ctx: LoginContext,
        clientId: String,
        username: String,
        password: String,
        redirectUri: String
    ): String {
        val authContext = ctx.getAuthContext()
        val authMetadata = authContext.getAuthorizationMetadata()
        val authEndpointUrl = authMetadata.getAuthorizationEndpointUri()
        val authRequest = buildAuthorizationRequest(authContext, clientId, redirectUri)

        val authCode = OAuthClient()
            .withLoginCredentials(username, password)
            .sendAuthorizationRequest(authEndpointUrl, authRequest)

        return authCode
    }

    @Deprecated("promote or remove")
    override suspend fun handleVPTokenRequest(
        ctx: LoginContext,
        authReq: AuthorizationRequestV0
    ): TokenResponse {
        log.info { "VPToken AuthorizationRequest: ${Json.encodeToString(authReq)}" }

        val clientId = authReq.clientId
        val nonce = authReq.nonce
        val state = authReq.state

        val dcql = authReq.dcqlQuery ?: error("No dcql_query in: $authReq")
        log.info { "VPToken DCQLQuery: ${dcql.toJson()}" }

        // Build the list of Credentials and associated PresentationSubmission
        //
        val (credJwts, vpSubmission) = buildPresentationSubmission(ctx, dcql)

        // Build the VPToken JWT
        //
        val jti = "${Uuid.random()}"
        val iat = Clock.System.now()
        val exp = iat + 5.minutes // 5 mins expiry

        val kid = ctx.didInfo.authenticationId()
        val vpTokenHeader = JWSHeader.Builder(JWSAlgorithm.ES256)
            .type(JOSEObjectType.JWT)
            .keyID(kid)
            .build()

        // Parse VPToken template with Jose to a MutableMap
        //
        val vpJson = """{
            "@context": [ "https://www.w3.org/2018/credentials/v1" ],
            "id": "$jti",
            "type": [ "VerifiablePresentation" ],
            "holder": "${ctx.did}",
            "verifiableCredential": ${credJwts.map { "\"${it.serialize()}\"" }}
        }"""
        val vpObj = JSONObjectUtils.parse(vpJson)

        val claimsBuilder = JWTClaimsSet.Builder()
            .jwtID(jti)
            .issuer(ctx.did)
            .subject(ctx.did)
            .audience(clientId)
            .issueTime(Date(iat.toEpochMilliseconds()))
            .notBeforeTime(Date(iat.toEpochMilliseconds()))
            .expirationTime(Date(exp.toEpochMilliseconds()))
            .claim("vp", vpObj)

        nonce?.also { claimsBuilder.claim("nonce", it) }
        state?.also { claimsBuilder.claim("state", it) }
        val vpTokenClaims = claimsBuilder.build()

        val vpTokenJwt = SignedJWT(vpTokenHeader, vpTokenClaims).signWithKey(ctx, kid)
        log.info { "VPToken Header: ${vpTokenJwt.header}" }
        log.info { "VPToken Claims: ${vpTokenJwt.jwtClaimsSet}" }

        val vpToken = vpTokenJwt.serialize()
        log.info { "VPToken: $vpToken" }
        log.info { "VPSubmission: ${vpSubmission.toJSON()}" }

        vpTokenJwt.verifyJwtSignature("VPToken", ctx.didInfo)

        return TokenResponse(vpToken = vpToken, presentationSubmission = vpSubmission)
    }

    // Private ---------------------------------------------------------------------------------------------------------

    private suspend fun buildAuthorizationRequestFromConfigIds(
        authContext: AuthorizationContext,
        configIds: List<String>,
        clientId: String,
        redirectUri: String,
        codeVerifier: String? = null
    ): AuthorizationRequestV0 {

        val issuerMetadata = authContext.getIssuerMetadata() as IssuerMetadataV0

        val scopes = issuerMetadata.credentialConfigurationsSupported
            .filter { (k, _) -> configIds.contains(k) }
            .mapNotNull { (_, v) -> v.scope }
            .toList()

        val builder = AuthorizationRequestBuilder()
            .withRedirectUri(redirectUri)
            .withIssuerMetadata(issuerMetadata)
            .withClientId(clientId)
            .withScopes(scopes)

        if (codeVerifier != null) {
            builder.withCodeChallengeMethod("S256")
            builder.withCodeVerifier(codeVerifier)
        }

        val authReq = builder.build()
        return authReq
    }

    private suspend fun buildAuthorizationRequestFromOffer(
        authContext: AuthorizationContext,
        credOffer: CredentialOffer,
        clientId: String,
        redirectUri: String,
        codeVerifier: String? = null
    ): AuthorizationRequestV0 {
        val ctx = requireNotNull(authContext.loginContext)

        val clientState = ctx.walletId

        val builder = AuthorizationRequestBuilder()
            .withCredentialOffer(credOffer)
            .withClientId(clientId)
            .withClientState(clientState)
            .withRedirectUri(redirectUri)

        if (codeVerifier != null) {
            builder.withCodeChallengeMethod("S256")
            builder.withCodeVerifier(codeVerifier)
        }

        val authReq = builder.build()
        return authReq
    }

    private suspend fun buildCredentialRequest(
        authContext: AuthorizationContext,
        cNonce: String?,
        credIdentifier: String? = null,
        credConfigIds: List<String>? = null
    ): CredentialRequest {

        val ctx = requireNotNull(authContext.loginContext)
        val issuerMetadata = authContext.getIssuerMetadata()
        val credentialIssuer = issuerMetadata.credentialIssuer

        val iat = Instant.now()
        val exp = iat.plusSeconds(300) // 5 mins expiry

        val proofJwt = when (credentialIssuer) {
            KNOWN_ISSUER_EBSI_V3 -> {
                val kid = ctx.didInfo.authenticationId()
                val proofHeader = JWSHeader.Builder(JWSAlgorithm.ES256)
                    .type(JOSEObjectType("openid4vci-proof+jwt"))
                    .keyID(kid)
                    .build()
                val proofClaimsBuilder = JWTClaimsSet.Builder()
                    .issuer(ctx.did)
                    .audience(credentialIssuer)
                    .issueTime(Date.from(iat))
                    .expirationTime(Date.from(exp))
                    .claim("nonce", cNonce)

                val authRequest = authContext.getAttachment(EBSI32_AUTHORIZATION_REQUEST_DRAFT11_ATTACHMENT_KEY)
                authRequest?.also { proofClaimsBuilder.claim("state", it.state) }

                val proofClaims = proofClaimsBuilder.build()
                SignedJWT(proofHeader, proofClaims).signWithKey(ctx, kid)
            }

            else -> {
                val kid = ctx.didInfo.keyId
                val ecKeyJson = widWalletService.exportKey(ctx, kid)
                val publicJwk = JWK.parse(ecKeyJson) as ECKey
                log.info { "PublicJwk: $publicJwk" }
                val proofHeader = JWSHeader.Builder(JWSAlgorithm.ES256)
                    .type(JOSEObjectType("openid4vci-proof+jwt"))
                    .jwk(publicJwk) // embed JWK directly
                    .build()
                val proofClaims = JWTClaimsSet.Builder()
                    .audience(credentialIssuer)
                    .issueTime(Date.from(iat))
                    .expirationTime(Date.from(exp))
                    .claim("nonce", cNonce)
                    .build()
                SignedJWT(proofHeader, proofClaims).signWithKey(ctx, kid)
            }
        }

        log.info { "ProofHeader: ${proofJwt.header}" }
        log.info { "ProofClaims: ${proofJwt.jwtClaimsSet}" }

        val credRequest = when (issuerMetadata) {
            is IssuerMetadataDraft11 -> {
                CredentialRequestDraft11(
                    format = "jwt_vc",
                    types = credConfigIds,
                    proof = CredentialRequestDraft11.Proof(
                        proofType = "jwt",
                        jwt = proofJwt.serialize()
                    )
                )
            }

            else -> {
                val credConfigId = credConfigIds?.firstOrNull()
                require(credIdentifier != null || credConfigId != null)
                { "Either credential_identifier OR credential_configuration_id" }
                require(!(credIdentifier != null && credConfigId != null))
                { "Cannot give both credential_identifier AND credential_configuration_id" }
                CredentialRequestV0(
                    credentialIdentifier = credIdentifier,
                    credentialConfigurationId = credConfigId,
                    proofs = CredentialRequestV0.Proofs(
                        jwt = listOf(proofJwt.serialize())
                    )
                )
            }
        }

        log.info { "CredentialRequest: ${credRequest.toJson()}" }
        return credRequest
    }

    /**
     * Extract the Credential from the CredentialResponse
     */
    private fun extractCredentialFromResponse(credResponse: CredentialResponse): SignedJWT {

        val signedJwts = when (credResponse) {
            is CredentialResponseDraft11 -> {
                listOf(SignedJWT.parse(credResponse.credential))
            }

            is CredentialResponseV0 -> {
                credResponse.credentials?.map { SignedJWT.parse(it.credential) }.orEmpty()
            }
        }
        if (signedJwts.isEmpty()) error("No credential in response")
        if (signedJwts.size > 1) error("Multiple credentials not supported")

        val signedJwt: SignedJWT = signedJwts[0]
        log.info { "CredentialJwt Header: ${signedJwt.header}" }
        log.info { "CredentialJwt Claims: ${signedJwt.jwtClaimsSet}" }

        val credJwt = W3CCredentialJwt.fromEncoded("${signedJwt.serialize()}")
        log.info { "Credential: ${credJwt.toJson()}" }

        return signedJwt
    }

    private suspend fun findMatchingCredentials(
        ctx: LoginContext,
        dcql: DCQLQuery
    ): List<Triple<WalletCredential, String, List<QueryClaim>?>> {
        val matcher = CredentialMatcherV10()
        val credentials = findCredentials(ctx) { true } // cache all credentials to avoid multiple API calls
        val res = dcql.credentials.mapNotNull { cq ->
            matcher.matchCredential(cq, credentials.asSequence())?.let { (wc, claims) ->
                Triple(wc, cq.id, claims)
            }
        }.onEach {
            log.info { "Matched: ${it.first.parsedDocument}" }
        }
        return res
    }

    private suspend fun sendCredentialRequest(
        authContext: AuthorizationContext,
        accessToken: TokenResponse,
        credIdentifier: String? = null,
        credConfigIds: List<String>? = null,
    ): CredentialResponse {

        val issuerMetadata = authContext.getIssuerMetadata()

        val cNonce = accessToken.cNonce ?: let {
            issuerMetadata as IssuerMetadataV0
            val res = http.post(issuerMetadata.nonceEndpoint!!)
            if (res.status != HttpStatusCode.OK)
                throw HttpStatusException(res.status, res.bodyAsText())
            val jsonObj = Json.decodeFromString<JsonObject>(res.bodyAsText())
            jsonObj.getValue("c_nonce").jsonPrimitive.content
        }

        val credRequest = buildCredentialRequest(authContext, cNonce, credIdentifier, credConfigIds)

        val res = http.post(issuerMetadata.credentialEndpoint) {
            header(HttpHeaders.Authorization, "Bearer ${accessToken.accessToken}")
            contentType(ContentType.Application.Json)
            setBody(credRequest.toJson())
        }
        val credResJson = res.bodyAsText()
        if (res.status != HttpStatusCode.OK)
            throw HttpStatusException(res.status, credResJson)

        val credResponse = CredentialResponse.fromJson(credResJson)
        log.info { "CredentialResponse: ${credResponse.toJson()}" }

        return credResponse
    }

    /**
     * Add Credential to WaltId storage
     */
    private fun storeCredential(ctx: LoginContext, format: CredentialFormat, signedJwt: SignedJWT) {
        widWalletService.addCredential(ctx.walletId, format, signedJwt)
    }

    private suspend fun validateCredential(ctx: LoginContext, signedJwt: SignedJWT): Pair<String, CredentialFormat> {

        val credJwt = W3CCredentialJwt.fromEncoded("${signedJwt.serialize()}")
        val credType = credJwt.types.first { it !in listOf("VerifiableAttestation", "VerifiableCredential") }

        val authContext = ctx.getAuthContext()
        val issuerMetadata = authContext.getIssuerMetadata()
        val format = requireNotNull(issuerMetadata.getCredentialFormat(credType)) { "No credential format for: $credType" }

        // Resolve issuer
        val issuerId = requireNotNull(credJwt.iss) { "No issuer claim" }
        log.info { "IssuerId: $issuerId" }

        // [TODO #331] Verify VC signature when iss is not did:key:*
        // https://github.com/tdiesler/nessus-identity/issues/331
        when {
            issuerId.startsWith("did:key:") -> {

                // Resolve DID Document locally
                val key = WaltIDServiceProvider.widDidService.resolveToKey(issuerId).getOrThrow()
                val jwk = JWK.parse("${key.exportJWKObject()}")
                log.info { "Issuer Jwk: $jwk" }

                val ecdsaVerifier = ECDSAVerifier(jwk.toECKey())
                when (credJwt) {
                    is W3CCredentialV11Jwt -> {
                        check(signedJwt.verify(ecdsaVerifier)) { "Invalid credential signature" }
                    }

                    is W3CCredentialSdV11Jwt -> {
                        val combined = "${signedJwt.serialize()}"
                        val jwsCompact = combined.substringBefore('~')  // keep only JWS
                        val jwsObj = JWSObject.parse(jwsCompact)
                        check(jwsObj.verify(ecdsaVerifier)) { "Invalid credential signature" }
                    }
                }
            }
        }

        // Validate JWT standard claims
        signedJwt.jwtClaimsSet.run {
            val now = Date()
            check(notBeforeTime == null || !now.before(notBeforeTime)) { "Credential not yet valid" }
            check(expirationTime == null || !now.after(expirationTime)) { "Credential expired" }
            check(this.issuer == issuerId) { "Issuer mismatch" }
        }

        return Pair(credType, format)
    }
}