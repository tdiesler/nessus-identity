package io.nessus.identity.service

import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
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
import io.ktor.client.*
import io.ktor.client.plugins.contentnegotiation.*
import io.ktor.client.request.*
import io.ktor.client.statement.*
import io.ktor.http.*
import io.ktor.serialization.kotlinx.json.*
import io.nessus.identity.config.ConfigProvider.requireEbsiConfig
import io.nessus.identity.config.ConfigProvider.requireIssuerConfig
import io.nessus.identity.extend.signWithKey
import io.nessus.identity.extend.verifyJwtSignature
import io.nessus.identity.service.AuthorizationContext.Companion.AUTHORIZATION_CODE_ATTACHMENT_KEY
import io.nessus.identity.service.AuthorizationContext.Companion.CODE_VERIFIER_ATTACHMENT_KEY
import io.nessus.identity.service.AuthorizationContext.Companion.EBSI32_AUTHORIZATION_REQUEST_DRAFT11_ATTACHMENT_KEY
import io.nessus.identity.service.AuthorizationContext.Companion.EBSI32_REQUEST_URI_OBJECT_ATTACHMENT_KEY
import io.nessus.identity.service.AuthorizationContext.Companion.USER_PIN_ATTACHMENT_KEY
import io.nessus.identity.service.IssuerService.Companion.KNOWN_ISSUER_EBSI_V3
import io.nessus.identity.service.LoginContext.Companion.USER_ATTACHMENT_KEY
import io.nessus.identity.service.OAuthClient.Companion.handleApiResponse
import io.nessus.identity.types.AuthorizationMetadata
import io.nessus.identity.types.AuthorizationRequest
import io.nessus.identity.types.AuthorizationRequestBuilder
import io.nessus.identity.types.AuthorizationRequestDraft11
import io.nessus.identity.types.AuthorizationRequestDraft11Builder
import io.nessus.identity.types.AuthorizationRequestV0
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
import io.nessus.identity.types.TokenRequest
import io.nessus.identity.types.TokenResponse
import io.nessus.identity.types.W3CCredentialJwt
import io.nessus.identity.types.W3CCredentialSdV11Jwt
import io.nessus.identity.types.W3CCredentialV11Jwt
import io.nessus.identity.waltid.WaltIDServiceProvider.widWalletService
import io.nessus.identity.waltid.authenticationId
import kotlinx.coroutines.delay
import kotlinx.serialization.json.*
import java.time.Instant
import java.util.*
import kotlin.random.Random
import kotlin.time.Clock
import kotlin.time.Duration.Companion.minutes
import kotlin.uuid.Uuid

// NativeWalletService =================================================================================================

class NativeWalletService : AbstractWalletService() {

    override val authorizationSvc = AuthorizationService.create()
    override val defaultClientId = requireIssuerConfig().clientId

    // Experimental ----------------------------------------------------------------------------------------------------

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

    override suspend fun createIDToken(ctx: LoginContext, authRequest: AuthorizationRequest): SignedJWT {

        val request = authRequest.request
        val requestUri = authRequest.requestUri
        require(requestUri != null || request != null) { "No 'request_uri' nor 'request'" }

        val idTokenRequestJwt = when {
            requestUri != null -> {
                log.info { "IDTokenRequest from: $requestUri" }

                val res = http.get(requestUri)
                if (res.status != HttpStatusCode.OK)
                    throw HttpStatusException(res.status, res.bodyAsText())

                val encodedJwt = res.bodyAsText()
                log.info { "IDTokenRequest: $encodedJwt" }

                SignedJWT.parse(encodedJwt)
            }
            else -> {
                log.info { "IDTokenRequest: $request" }
                SignedJWT.parse(request)
            }
        }
        val idTokenJwt = authorizationSvc.createIDTokenJwt(ctx, authRequest, idTokenRequestJwt)
        return idTokenJwt
    }

    override suspend fun getAccessTokenFromAuthorizationCode(
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

    // WalletService ---------------------------------------------------------------------------------------------------

    /**
     * Get the authorization metadata
     */
    override fun getAuthorizationMetadata(ctx: LoginContext): AuthorizationMetadata {
        val targetUri = "$endpointUri/${ctx.targetId}"
        return authorizationSvc.buildAuthorizationMetadata(targetUri)
    }

    override suspend fun getAccessTokenFromCredentialOffer(
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

        if (credOffer.credentialIssuer == KNOWN_ISSUER_EBSI_V3) {
            val authRequest = buildAuthorizationRequestFromOffer(ctx, credOffer)
            val authEndpointUri = issuerMetadata.getAuthorizationMetadata().getAuthorizationEndpointUri()
            val authCode = sendAuthorizationRequest(ctx, authEndpointUri, authRequest)
            val tokenRes = getAccessTokenFromAuthorizationCode(ctx, authCode)
            return tokenRes
        }

        error("Cannot get AccessToken from CredentialOffer")
    }

    /**
     * Get the CredentialOffer for the given credential offer uri
     */
    override suspend fun getCredentialOfferFromUri(offerUri: String): CredentialOfferV0 {
        val credOfferRes = http.get(offerUri)
        val credOffer = (handleApiResponse(credOfferRes) as CredentialOfferV0)
        log.info { "CredentialOffer: ${credOffer.toJson()}" }
        return credOffer
    }

    /**
     * Holder gets a Credential from an Issuer
     * https://hub.ebsi.eu/conformance/build-solutions/issue-to-holder-functional-flows#in-time-issuance
     */
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
        val (_, format) = W3CCredentialValidator.validateCredential(authContext, signedJwt)

        // Store the Credential
        //
        storeCredential(authContext, format, signedJwt)

        val credJwt = W3CCredentialJwt.fromEncoded("${signedJwt.serialize()}")
        return credJwt
    }

    override suspend fun getCredentialFromOffer(ctx: LoginContext, credOffer: CredentialOffer): W3CCredentialJwt {

        val authContext = ctx.getAuthContext().withCredentialOffer(credOffer)

        val issuerMetadata = authContext.getIssuerMetadata()
        val accessToken = getAccessTokenFromCredentialOffer(ctx, credOffer)

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
        val (_, format) = W3CCredentialValidator.validateCredential(authContext, signedJwt)

        // Store the Credential
        //
        storeCredential(authContext, format, signedJwt)

        val credJwt = W3CCredentialJwt.fromEncoded("${signedJwt.serialize()}")
        return credJwt
    }

    // LegacyWalletService ---------------------------------------------------------------------------------------------

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

    override suspend fun buildPresentationSubmission(
        ctx: LoginContext,
        dcql: DCQLQuery,
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

    override suspend fun getAccessTokenFromDirectAccess(
        ctx: LoginContext,
        clientId: String,
    ): TokenResponse {

        val tokenEndpointUrl = getAuthorizationMetadata(ctx).getAuthorizationTokenEndpointUri()
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

    /**
     * The Authorization Request parameter contains a DCQL query that describes the requirements of the Credential(s) that the Verifier is requesting to be presented.
     * Such requirements could include what type of Credential(s), in what format(s), which individual Claims within those Credential(s) (Selective Disclosure), etc.
     * The Wallet processes the Request Object and determines what Credentials are available matching the Verifier's request.
     * The Wallet also authenticates the End-User and gathers their consent to present the requested Credentials.
     *
     * The Wallet prepares the Presentation(s) of the Credential(s) that the End-User has consented to.
     * It then sends to the Verifier an Authorization Response where the Presentation(s) are contained in the vp_token parameter.
     *
     * https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-3
     */
    override suspend fun handleVPTokenRequest(ctx: LoginContext, authReq: AuthorizationRequestV0): TokenResponse {

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

    // Private -------------------------------------------------------------------------------------------------------------------------------------------------

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
        credConfigIds: List<String>? = null // [TODO] make credConfigId a single value
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

        val credRequest = when (credentialIssuer) {
            KNOWN_ISSUER_EBSI_V3 -> {
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
    private fun storeCredential(authContext: AuthorizationContext, format: CredentialFormat, signedJwt: SignedJWT) {
        authContext.loginContext?.also {
            widWalletService.addCredential(it.walletId, format, signedJwt)
        }
    }
}