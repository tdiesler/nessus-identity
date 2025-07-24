package io.nessus.identity.service

import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import id.walt.oid4vc.OpenID4VCI
import id.walt.oid4vc.data.AuthorizationDetails
import id.walt.oid4vc.data.CredentialOffer
import id.walt.oid4vc.data.GrantType
import id.walt.oid4vc.data.OfferedCredential
import id.walt.oid4vc.data.OpenIDClientMetadata
import id.walt.oid4vc.data.OpenIDProviderMetadata
import id.walt.oid4vc.requests.AuthorizationRequest
import id.walt.oid4vc.requests.CredentialRequest
import id.walt.oid4vc.responses.CredentialResponse
import id.walt.oid4vc.responses.TokenResponse
import io.github.oshai.kotlinlogging.KotlinLogging
import io.ktor.client.HttpClient
import io.ktor.client.plugins.contentnegotiation.ContentNegotiation
import io.ktor.client.request.get
import io.ktor.client.request.header
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.client.statement.bodyAsText
import io.ktor.http.ContentType
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.http.URLBuilder
import io.ktor.http.contentType
import io.ktor.serialization.kotlinx.json.json
import io.nessus.identity.config.ConfigProvider.authEndpointUri
import io.nessus.identity.service.AttachmentKeys.AUTH_REQUEST_ATTACHMENT_KEY
import io.nessus.identity.service.AttachmentKeys.AUTH_REQUEST_CODE_VERIFIER_ATTACHMENT_KEY
import io.nessus.identity.service.AttachmentKeys.CREDENTIAL_OFFER_ATTACHMENT_KEY
import io.nessus.identity.service.AttachmentKeys.ISSUER_METADATA_ATTACHMENT_KEY
import io.nessus.identity.service.AttachmentKeys.REQUEST_URI_OBJECT_ATTACHMENT_KEY
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

    fun buildAuthorizationRequest(ctx: OIDCContext, authDetails: AuthorizationDetails? = null): AuthorizationRequest {

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
        val clientMetadata = OpenIDClientMetadata(customParameters = mapOf(
            "authorization_endpoint" to JsonPrimitive(authRedirectUri)))

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
            redirectUri = authRedirectUri,
            issuerState = issuerState
        )

        ctx.putAttachment(AUTH_REQUEST_ATTACHMENT_KEY, authRequest)
        ctx.putAttachment(AUTH_REQUEST_CODE_VERIFIER_ATTACHMENT_KEY, codeVerifier)
        log.info { "AuthorizationRequest: ${Json.encodeToString(authRequest)}" }

        return authRequest
    }

    suspend fun buildCredentialRequest(ctx: OIDCContext, offeredCred: OfferedCredential, accessToken: TokenResponse): CredentialRequest {

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
            val tokenReq = AuthService.createTokenRequestAuthCode(ctx, authCode)
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