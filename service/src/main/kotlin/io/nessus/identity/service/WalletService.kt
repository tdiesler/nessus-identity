package io.nessus.identity.service

import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.util.JSONObjectUtils
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import id.walt.oid4vc.OpenID4VCI
import id.walt.oid4vc.data.AuthorizationDetails
import id.walt.oid4vc.data.CredentialFormat
import id.walt.oid4vc.data.CredentialOffer
import id.walt.oid4vc.data.GrantType
import id.walt.oid4vc.data.OfferedCredential
import id.walt.oid4vc.data.OpenIDClientMetadata
import id.walt.oid4vc.data.OpenIDProviderMetadata
import id.walt.oid4vc.data.dif.DescriptorMapping
import id.walt.oid4vc.data.dif.PresentationDefinition
import id.walt.oid4vc.data.dif.PresentationSubmission
import id.walt.oid4vc.requests.AuthorizationRequest
import id.walt.oid4vc.requests.CredentialRequest
import id.walt.oid4vc.requests.TokenRequest
import id.walt.oid4vc.responses.CredentialResponse
import id.walt.oid4vc.responses.TokenResponse
import id.walt.w3c.utils.VCFormat
import io.github.oshai.kotlinlogging.KotlinLogging
import io.ktor.client.HttpClient
import io.ktor.client.plugins.contentnegotiation.ContentNegotiation
import io.ktor.client.request.forms.FormDataContent
import io.ktor.client.request.get
import io.ktor.client.request.header
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.client.statement.bodyAsText
import io.ktor.http.ContentType
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.http.Parameters
import io.ktor.http.URLBuilder
import io.ktor.http.contentType
import io.ktor.serialization.kotlinx.json.json
import io.nessus.identity.config.ConfigProvider.authEndpointUri
import io.nessus.identity.service.AttachmentKeys.AUTH_CODE_ATTACHMENT_KEY
import io.nessus.identity.service.AttachmentKeys.AUTH_REQUEST_ATTACHMENT_KEY
import io.nessus.identity.service.AttachmentKeys.AUTH_REQUEST_CODE_VERIFIER_ATTACHMENT_KEY
import io.nessus.identity.service.AttachmentKeys.CREDENTIAL_OFFER_ATTACHMENT_KEY
import io.nessus.identity.service.AttachmentKeys.ISSUER_METADATA_ATTACHMENT_KEY
import io.nessus.identity.service.AttachmentKeys.REQUEST_URI_OBJECT_ATTACHMENT_KEY
import io.nessus.identity.types.JwtCredential
import io.nessus.identity.waltid.WaltidServiceProvider.widWalletSvc
import io.nessus.identity.waltid.authenticationId
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import java.security.MessageDigest
import java.time.Instant
import java.util.Base64
import java.util.Date
import kotlin.random.Random
import kotlin.uuid.ExperimentalUuidApi
import kotlin.uuid.Uuid

// WalletService =======================================================================================================

object WalletService {

    val log = KotlinLogging.logger {}

    fun addCredentialOffer(ctx: OIDCContext, credOffer: CredentialOffer) {
        ctx.putAttachment(CREDENTIAL_OFFER_ATTACHMENT_KEY, credOffer)
    }

    fun addCredential(ctx: OIDCContext, credRes: CredentialResponse) {
        val walletId = ctx.walletId
        val credJwt = credRes.toSignedJWT()
        val format = credRes.format as CredentialFormat

        // Verify that we can unmarshall the credential
        Json.decodeFromString<JwtCredential>("${credJwt.payload}")

        widWalletSvc.addCredential(walletId, format, credJwt)
    }

    fun buildAuthorizationRequest(
        ctx: OIDCContext,
        authDetails: AuthorizationDetails? = null,
        vpDefinition: PresentationDefinition? = null,
    ): AuthorizationRequest {

        // The Holder starts by requesting access for the desired credential from the Issuer's Authorisation Server.
        // The client_metadata.authorization_endpoint is used for the redirect location associated with the vp_token and id_token.
        // If client_metadata fails to provide the required information, the default configuration (openid://) will be used instead.

        val rndBytes = Random.Default.nextBytes(32)
        val sha256 = MessageDigest.getInstance("SHA-256")
        val codeVerifier = Base64.getUrlEncoder().withoutPadding().encodeToString(rndBytes)
        val codeVerifierHash = sha256.digest(codeVerifier.toByteArray(Charsets.US_ASCII))
        val codeChallenge = Base64.getUrlEncoder().withoutPadding().encodeToString(codeVerifierHash)

        // Build AuthRequestUrl
        //
        val authRedirectUri = "$authEndpointUri/${ctx.targetId}"
        val clientMetadata = OpenIDClientMetadata(
            customParameters = mapOf(
                "authorization_endpoint" to JsonPrimitive(authRedirectUri)
            )
        )

        val credOffer = ctx.getAttachment(CREDENTIAL_OFFER_ATTACHMENT_KEY)
        val issuerState = credOffer?.grants[GrantType.authorization_code.value]?.issuerState

        val authRequest = AuthorizationRequest(
            scope = setOf("openid"),
            clientId = ctx.did,
            state = ctx.walletId,
            clientMetadata = clientMetadata,
            codeChallenge = codeChallenge,
            codeChallengeMethod = "S256",
            authorizationDetails = authDetails?.let { listOf(authDetails) },
            presentationDefinition = vpDefinition,
            redirectUri = authRedirectUri,
            issuerState = issuerState
        )

        ctx.putAttachment(AUTH_REQUEST_ATTACHMENT_KEY, authRequest)
        ctx.putAttachment(AUTH_REQUEST_CODE_VERIFIER_ATTACHMENT_KEY, codeVerifier)
        log.info { "AuthorizationRequest: ${Json.encodeToString(authRequest)}" }

        return authRequest
    }

    suspend fun buildCredentialRequest(
        ctx: OIDCContext,
        offeredCred: OfferedCredential,
        accessToken: TokenResponse
    ): CredentialRequest {

        val cNonce = accessToken.cNonce
            ?: throw IllegalStateException("No c_nonce")

        val iat = Instant.now()
        val exp = iat.plusSeconds(300) // 5 mins expiry

        val kid = ctx.didInfo.authenticationId()

        val credReqHeader = JWSHeader.Builder(JWSAlgorithm.ES256)
            .type(JOSEObjectType("openid4vci-proof+jwt"))
            .keyID(kid)
            .build()

        val issuerUri = ctx.issuerMetadata.credentialIssuer
        val claimsBuilder = JWTClaimsSet.Builder()
            .issuer(ctx.did)
            .audience(issuerUri)
            .issueTime(Date.from(iat))
            .expirationTime(Date.from(exp))
            .claim("nonce", cNonce)

        ctx.maybeAuthRequest?.state?.also {
            claimsBuilder.claim("state", it)
        }
        val credReqClaims = claimsBuilder.build()

        val credReqJwt = SignedJWT(credReqHeader, credReqClaims).signWithKey(ctx, kid)
        log.info { "CredentialRequest Header: ${credReqJwt.header}" }
        log.info { "CredentialRequest Claims: ${credReqJwt.jwtClaimsSet}" }

        val credentialTypes = offeredCred.types
            ?: throw IllegalStateException("No credential types")

        val credReqJson = Json.encodeToString(buildJsonObject {
            put("types", JsonArray(credentialTypes.map { JsonPrimitive(it) }))
            put("format", JsonPrimitive("jwt_vc"))
            put("proof", buildJsonObject {
                put("proof_type", JsonPrimitive("jwt"))
                put("jwt", JsonPrimitive(credReqJwt.serialize()))
            })
        })

        val credReq = Json.decodeFromString<CredentialRequest>(credReqJson)
        log.info { "CredentialRequest: ${Json.encodeToString(credReq)}" }

        return credReq
    }

    suspend fun createIDToken(ctx: OIDCContext, reqParams: Map<String, String>): SignedJWT {

        // Verify required query params
        for (key in listOf("client_id", "redirect_uri", "response_type")) {
            reqParams[key] ?: throw IllegalStateException("Cannot find $key")
        }

        // The Wallet answers the ID Token Request by providing the id_token in the redirect_uri as instructed by response_mode of direct_post.
        // The id_token must be signed with the DID document's authentication key.

        val clientId = reqParams["client_id"] as String
        val responseType = reqParams["response_type"] as String

        if (responseType != "id_token")
            throw IllegalStateException("Unexpected response_type: $responseType")

        val nonce = reqParams["nonce"]
        val state = reqParams["state"]

        val iat = Instant.now()
        val exp = iat.plusSeconds(300) // 5 mins expiry

        val kid = ctx.didInfo.authenticationId()

        val idTokenHeader = JWSHeader.Builder(JWSAlgorithm.ES256)
            .type(JOSEObjectType.JWT)
            .keyID(kid)
            .build()

        val jwtBuilder = JWTClaimsSet.Builder()
            .issuer(ctx.did)
            .subject(ctx.did)
            .audience(clientId)
            .issueTime(Date.from(iat))
            .expirationTime(Date.from(exp))
            .claim("nonce", nonce)

        nonce?.also { jwtBuilder.claim("nonce", it) }
        state?.also { jwtBuilder.claim("state", it) }
        val idTokenClaims = jwtBuilder.build()

        val idTokenJwt = SignedJWT(idTokenHeader, idTokenClaims).signWithKey(ctx, kid)
        log.info { "IDToken Header: ${idTokenJwt.header}" }
        log.info { "IDToken Claims: ${idTokenJwt.jwtClaimsSet}" }

        log.info { "IDToken: ${idTokenJwt.serialize()}" }
        if (!idTokenJwt.verifyJwt(ctx.didInfo))
            throw IllegalStateException("IDToken signature verification failed")

        return idTokenJwt
    }

    suspend fun sendIDToken(ctx: OIDCContext, redirectUri: String, idTokenJwt: SignedJWT): String {

        log.info { "Send IDToken: $redirectUri" }
        val formData = mutableMapOf(
            "id_token" to idTokenJwt.serialize(),
        )
        val isTokenClaims = idTokenJwt.jwtClaimsSet
        isTokenClaims.getClaim("state")?.also { formData["state"] = "$it" }

        formData.forEach { (k, v) -> log.info { "  $k=$v" } }

        val res = http.post(redirectUri) {
            contentType(ContentType.Application.FormUrlEncoded)
            setBody(FormDataContent(Parameters.build {
                formData.forEach { (k, v) -> append(k, v) }
            }))
        }

        if (res.status != HttpStatusCode.Found)
            throw HttpStatusException(res.status, res.bodyAsText())

        val location = res.headers["location"]?.also {
            log.info { "IDToken Response: $it" }
        } ?: throw IllegalStateException("Cannot find 'location' in headers")

        val authCode = urlQueryToMap(location)["code"]?.also {
            ctx.putAttachment(AUTH_CODE_ATTACHMENT_KEY, it)
        } ?: throw IllegalStateException("No authorization code")

        return authCode
    }

    suspend fun createVPToken(ctx: OIDCContext, reqParams: Map<String, String>): SignedJWT {
        val (vpTokenJwt, _) = createVPTokenWithPresentationSubmission(ctx, reqParams)
        return vpTokenJwt
    }

        @OptIn(ExperimentalUuidApi::class)
    suspend fun createVPTokenWithPresentationSubmission(ctx: OIDCContext, reqParams: Map<String, String>): Pair<SignedJWT, PresentationSubmission> {

        // Verify required query params
        for (key in listOf("client_id", "response_type")) {
            reqParams[key] ?: throw IllegalStateException("Cannot find $key")
        }

        val clientId = reqParams["client_id"] as String
        val responseType = reqParams["response_type"] as String

        if (responseType != "vp_token")
            throw IllegalStateException("Unexpected response_type: $responseType")

        var authReq = ctx.getAttachment(AUTH_REQUEST_ATTACHMENT_KEY)

        // Final Qualification Credential use case ...
        //
        //  - EBSI offers the CTWalletQualificationCredential
        //  - Holder sends an AuthorizationRequest, EBSI responds with an 302 Redirect (WalletService.sendAuthorizationRequest)
        //  - Cloudflare may deny that redirect URL because of a very large 'request' query parameter
        //  - The content of that request parameter is a serialized AuthorizationRequest object
        //  - We rewrite the redirect URL using a request_uri parameter, which resolves to that AuthorizationRequest
        //  - Here, we restore that AuthorizationRequest and use it's PresentationDefinition to build the VPToken

        val requestUri = reqParams["request_uri"]
        if (requestUri != null) {

            if (!requestUri.startsWith(authEndpointUri))
                throw IllegalStateException("Unexpected request_uri: $requestUri")

            val reqObjectId = urlQueryToMap(requestUri)["request_object"]
            if (reqObjectId == null)
                throw IllegalStateException("No request_object in: $requestUri")

            // [TODO] Select request_uri object by id
            authReq = ctx.assertAttachment(REQUEST_URI_OBJECT_ATTACHMENT_KEY) as AuthorizationRequest
        }
        log.info { "VPToken AuthorizationRequest: ${Json.encodeToString(authReq)}" }

        val vpdef = authReq?.presentationDefinition
            ?: throw IllegalStateException("No presentationDefinition in: $authReq")

        val jti = "${Uuid.random()}"
        val iat = Instant.now()
        val exp = iat.plusSeconds(300) // 5 mins expiry

        val kid = ctx.didInfo.authenticationId()
        val vpTokenHeader = JWSHeader.Builder(JWSAlgorithm.ES256)
            .type(JOSEObjectType.JWT)
            .keyID(kid)
            .build()

        val vpJson = """{
            "@context": [ "https://www.w3.org/2018/credentials/v1" ],
            "id": "$jti",
            "type": [ "VerifiablePresentation" ],
            "holder": "${ctx.did}",
            "verifiableCredential": []
        }"""
        val vpObj = JSONObjectUtils.parse(vpJson)

        @Suppress("UNCHECKED_CAST")
        val vcArray = vpObj["verifiableCredential"] as MutableList<String>

        val descriptorMappings = mutableListOf<DescriptorMapping>()
        val matchingCredentials = widWalletSvc.findCredentials(ctx, vpdef).toMap()

        for (ind in vpdef.inputDescriptors) {

            val wc = matchingCredentials[ind.id]
            if (wc == null) {
                log.warn { "No matching credential for: ${ind.id}" }
                continue
            }

            log.info { "Found matching credential for: ${ind.id}" }

            val n = vcArray.size
            val dm = DescriptorMapping(
                id = ind.id,
                path = "$",
                format = VCFormat.jwt_vp,
                pathNested = DescriptorMapping(
                    id = ind.id,
                    path = "$.vp.verifiableCredential[$n]",
                    format = VCFormat.jwt_vc,
                )
            )

            descriptorMappings.add(dm)
            vcArray.add(wc.document)
        }

        val vpSubmission = PresentationSubmission(
            id = "${Uuid.random()}",
            definitionId = vpdef.id,
            descriptorMap = descriptorMappings
        )

        val claimsBuilder = JWTClaimsSet.Builder()
            .jwtID(jti)
            .issuer(ctx.did)
            .subject(ctx.did)
            .audience(clientId)
            .issueTime(Date.from(iat))
            .notBeforeTime(Date.from(iat))
            .expirationTime(Date.from(exp))
            .claim("vp", vpObj)

        authReq.nonce?.also { claimsBuilder.claim("nonce", it) }
        authReq.state?.also { claimsBuilder.claim("state", it) }
        val vpTokenClaims = claimsBuilder.build()

        val vpTokenJwt = SignedJWT(vpTokenHeader, vpTokenClaims).signWithKey(ctx, kid)
        log.info { "VPToken Header: ${vpTokenJwt.header}" }
        log.info { "VPToken Claims: ${vpTokenJwt.jwtClaimsSet}" }

        val vpToken = vpTokenJwt.serialize()
        log.info { "VPToken: $vpToken" }

        if (!vpTokenJwt.verifyJwt(ctx.didInfo))
            throw IllegalStateException("VPToken signature verification failed")

        return Pair(vpTokenJwt, vpSubmission)
    }

    suspend fun sendVPToken(ctx: OIDCContext, vpTokenJwt: SignedJWT, vpSubmission: PresentationSubmission): String {

        val reqObject = ctx.assertAttachment(REQUEST_URI_OBJECT_ATTACHMENT_KEY) as AuthorizationRequest

        val redirectUri = reqObject.redirectUri
            ?: throw IllegalStateException("No redirectUri in: $reqObject")

        val state = reqObject.state
            ?: throw IllegalStateException("No state in: $reqObject")

        log.info { "Send VPToken: $redirectUri" }
        val formData = mapOf(
            "vp_token" to "${vpTokenJwt.serialize()}",
            "presentation_submission" to Json.encodeToString(vpSubmission),
            "state" to state,
        ).also {
            it.forEach { (k, v) -> log.info { "  $k=$v" } }
        }

        val res = http.post(redirectUri) {
            contentType(ContentType.Application.FormUrlEncoded)
            setBody(FormDataContent(Parameters.build {
                formData.forEach { (k, v) -> append(k, v) }
            }))
        }

        if (res.status != HttpStatusCode.Found)
            throw HttpStatusException(res.status, res.bodyAsText())

        val location = res.headers["location"]?.also {
            log.info { "VPToken Response: $it" }
        } ?: throw IllegalStateException("Cannot find 'location' in headers")

        val authCode = urlQueryToMap(location)["code"]?.also {
            ctx.putAttachment(AUTH_CODE_ATTACHMENT_KEY, it)
        } ?: throw IllegalStateException("No authorization code")

        return authCode
    }

    fun createTokenRequestAuthCode(ctx: OIDCContext, authCode: String): TokenRequest {

        val tokenRequest = TokenRequest.AuthorizationCode(
            clientId = ctx.did,
            redirectUri = ctx.authRequest.redirectUri,
            codeVerifier = ctx.authRequestCodeVerifier,
            code = authCode,
        )
        return tokenRequest
    }

    suspend fun getCredentialOfferFromUri(ctx: OIDCContext, offerUri: String): CredentialOffer {
        val credOffer = OpenID4VCI.parseAndResolveCredentialOfferRequestUrl(offerUri)
        ctx.putAttachment(CREDENTIAL_OFFER_ATTACHMENT_KEY, credOffer)
        return credOffer
    }

    suspend fun getCredentialFromOffer(ctx: OIDCContext, credOffer: CredentialOffer): CredentialResponse {

        val offeredCred = resolveOfferedCredential(ctx, credOffer)

        val accessToken = credOffer.getPreAuthorizedGrantDetails()?.let {
            AuthService.sendTokenRequestPreAuthorized(ctx, it)
        } ?: run {
            val issuer = credOffer.credentialIssuer
            val authDetails = AuthorizationDetails.fromOfferedCredential(offeredCred, issuer)
            val authRequest = buildAuthorizationRequest(ctx, authDetails)
            val authCode = sendAuthorizationRequest(ctx, authRequest)
            val tokenReq = createTokenRequestAuthCode(ctx, authCode)
            AuthService.sendTokenRequestAuthCode(ctx, tokenReq)
        }

        val credReq = buildCredentialRequest(ctx, offeredCred, accessToken)
        val credRes = sendCredentialRequest(ctx, credReq)

        return credRes
    }

    suspend fun getDeferredCredential(ctx: OIDCContext, acceptanceToken: String): CredentialResponse {

        val deferredCredentialEndpoint = ctx.issuerMetadata.deferredCredentialEndpoint
            ?: throw IllegalStateException("No credential_endpoint")

        log.info { "Send Deferred Credential Request: $deferredCredentialEndpoint" }

        val res = http.post(deferredCredentialEndpoint) {
            header(HttpHeaders.Authorization, "Bearer $acceptanceToken")
        }
        if (res.status != HttpStatusCode.OK)
            throw HttpStatusException(res.status, res.bodyAsText())

        val credJson = res.bodyAsText()
        log.info { "Deferred Credential Response: $credJson" }

        val credRes = Json.decodeFromString<CredentialResponse>(credJson)

        val credJwt = credRes.toSignedJWT()
        log.info { "Credential Header: ${credJwt.header}" }
        log.info { "Credential Claims: ${credJwt.jwtClaimsSet}" }

        return credRes
    }

    suspend fun resolveIssuerMetadata(issuerUrl: String): OpenIDProviderMetadata {
        val issuerMetadataUrl = "$issuerUrl/.well-known/openid-credential-issuer"
        return http.get(issuerMetadataUrl).bodyAsText().let {
            OpenIDProviderMetadata.fromJSONString(it)
        }
    }

    /**
     * Resolve the CredentialOffer to an OfferedCredential using the Issuer's metadata
     */
    suspend fun resolveOfferedCredential(ctx: OIDCContext, credOffer: CredentialOffer): OfferedCredential {

        // Get issuer Metadata (on demand)
        //
        if (!ctx.hasAttachment(ISSUER_METADATA_ATTACHMENT_KEY)) {
            val issuerMetadata = resolveIssuerMetadata(credOffer.credentialIssuer)
            log.info { "Issuer Metadata: ${Json.encodeToString(issuerMetadata)}" }
            ctx.putAttachment(ISSUER_METADATA_ATTACHMENT_KEY, issuerMetadata)
        }

        val issuerMetadata = ctx.issuerMetadata as? OpenIDProviderMetadata.Draft11
            ?: throw IllegalStateException("Expected Draft11 metadata, but got ${ctx.issuerMetadata::class.simpleName}")

        // Resolve Offered Credential
        //
        val offeredCredentials = OpenID4VCI.resolveOfferedCredentials(credOffer, issuerMetadata)
        log.info { "Offered Credentials: ${Json.encodeToString(offeredCredentials)}" }
        if (offeredCredentials.size > 1) log.warn { "Multiple offered credentials, using first" }
        val offeredCredential = offeredCredentials.first()

        return offeredCredential
    }

    // Private ---------------------------------------------------------------------------------------------------------

    @OptIn(ExperimentalUuidApi::class)
    private suspend fun sendAuthorizationRequest(ctx: OIDCContext, authRequest: AuthorizationRequest): String {

        val authReqUrl = URLBuilder("${ctx.authorizationServer}/authorize").apply {
            authRequest.toHttpParameters().forEach { (k, lst) -> lst.forEach { v -> parameters.append(k, v) } }
        }.buildString()

        log.info { "Send AuthorizationRequest: $authReqUrl" }
        authRequest.toHttpParameters().forEach { (k, lst) -> lst.forEach { v -> log.info { "  $k=$v" } } }

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

        if (res.status == HttpStatusCode.Found) {

            log.error { "Redirect response: ${res.status}" }
            res.headers.forEach { k, lst -> lst.forEach { v -> log.debug { "  $k: $v" } } }

            // First try access the location as given
            val locationUri = res.headers["location"] as String
            val urlBase = locationUri.substringBefore('?')
            val queryParams = urlQueryToMap(locationUri)
            res = http.get(locationUri)

            // Cloudflare may reject the request because of url size limits or other WAF rules
            // We try again using 'request_uri' syntax with an in-memory request object
            // https://openid.net/specs/openid-connect-core-1_0.html#UseRequestUri
            if (res.status == HttpStatusCode.BadRequest) {
                log.warn { "Direct redirect [length=${locationUri.length}] failed with: ${res.status}" }
                if (queryParams["request"] != null) {

                    // Redirect location is expected to be an Authorization Request
                    val queryParamsExt = queryParams.mapValues { (_, v) -> listOf(v) }
                    val authReq = AuthorizationRequest.fromHttpParameters(queryParamsExt)

                    // Store the AuthorizationRequest in memory
                    val reqObjectId = "${Uuid.random()}"
                    ctx.putAttachment(REQUEST_URI_OBJECT_ATTACHMENT_KEY, authReq)

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

        log.info { "AuthorizationCode: ${ctx.authCode}" }
        return ctx.authCode
    }

    private suspend fun sendCredentialRequest(ctx: OIDCContext, credReq: CredentialRequest): CredentialResponse {

        val accessToken = ctx.accessToken
        val credentialEndpoint = ctx.issuerMetadata.credentialEndpoint
            ?: throw IllegalStateException("No credential_endpoint")

        val credReqJson = Json.encodeToString(credReq)
        log.info { "Send CredentialRequest: $credentialEndpoint" }
        log.info { "  $credReqJson" }

        val res = http.post(credentialEndpoint) {
            header(HttpHeaders.Authorization, "Bearer ${accessToken.serialize()}")
            contentType(ContentType.Application.Json)
            setBody(credReqJson)
        }
        if (res.status != HttpStatusCode.OK)
            throw HttpStatusException(res.status, res.bodyAsText())

        val credJson = res.bodyAsText()
        log.info { "Credential Response: $credJson" }

        val credRes = Json.decodeFromString<CredentialResponse>(credJson)

        // In-Time CredentialResponses MUST have a 'format'
        if (credRes.format != null) {
            val credJwt = credRes.toSignedJWT()
            log.info { "Credential Header: ${credJwt.header}" }
            log.info { "Credential Claims: ${credJwt.jwtClaimsSet}" }
        }

        return credRes
    }
}