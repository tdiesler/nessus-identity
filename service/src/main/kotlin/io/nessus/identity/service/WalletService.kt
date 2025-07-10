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
import id.walt.oid4vc.responses.CredentialResponse
import id.walt.oid4vc.responses.TokenResponse
import io.github.oshai.kotlinlogging.KotlinLogging
import io.ktor.client.*
import io.ktor.client.plugins.contentnegotiation.*
import io.ktor.client.request.*
import io.ktor.client.statement.*
import io.ktor.http.*
import io.ktor.serialization.kotlinx.json.*
import io.nessus.identity.api.WalletServiceApi
import io.nessus.identity.config.ConfigProvider.authEndpointUri
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

object WalletService : WalletServiceApi {

    val log = KotlinLogging.logger {}

    override suspend fun getCredentialFromUri(ctx: FlowContext, offerUri: String): CredentialResponse {

        val credOffer = OpenID4VCI.parseAndResolveCredentialOfferRequestUrl(offerUri)
        val credResponse = getCredentialFromOffer(ctx, credOffer)

        return credResponse
    }

    override suspend fun getCredentialFromOffer(ctx: FlowContext, credOffer: CredentialOffer): CredentialResponse {

        val offeredCred = resolveOfferedCredentials(ctx, credOffer)

        val tokenResponse = credOffer.getPreAuthorizedGrantDetails()?.let {
            AuthService.sendTokenRequestPreAuthorized(ctx, it)
        } ?: run {
            val authRequest = authorizationRequestFromCredentialOffer(ctx, offeredCred)
            val authCode = sendAuthorizationRequest(ctx, authRequest)
            AuthService.sendTokenRequestAuthCode(ctx, authCode)
        }

        val credResponse = sendCredentialRequest(ctx, tokenResponse)
        return credResponse
    }

    override suspend fun getDeferredCredential(cex: FlowContext, acceptanceToken: String): CredentialResponse {

        val deferredCredentialEndpoint = cex.issuerMetadata.deferredCredentialEndpoint
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

        cex.credResponse = credRes
        return credRes
    }

    suspend fun resolveOpenIDProviderMetadata(issuerUrl: String): OpenIDProviderMetadata {
        val issuerMetadataUrl = "$issuerUrl/.well-known/openid-credential-issuer"
        return http.get(issuerMetadataUrl).bodyAsText().let {
            OpenIDProviderMetadata.fromJSONString(it)
        }
    }

    // Private ---------------------------------------------------------------------------------------------------------

    private fun authorizationRequestFromCredentialOffer(cex: FlowContext, offeredCred: OfferedCredential): AuthorizationRequest {

        // The Wallet will start by requesting access for the desired credential from the Auth Mock (Authorisation Server).
        // The client_metadata.authorization_endpoint is used for the redirect location associated with the vp_token and id_token.
        // If client_metadata fails to provide the required information, the default configuration (openid://) will be used instead.

        val rndBytes = Random.Default.nextBytes(32)
        val codeVerifier = Base64.getUrlEncoder().withoutPadding().encodeToString(rndBytes)
        val sha256 = MessageDigest.getInstance("SHA-256")
        val codeVerifierHash = sha256.digest(codeVerifier.toByteArray(Charsets.US_ASCII))
        val codeChallenge = Base64.getUrlEncoder().withoutPadding().encodeToString(codeVerifierHash)

        cex.authRequestCodeVerifier = codeVerifier

        // Build AuthRequestUrl
        //
        val authEndpointUri = "$authEndpointUri/${cex.subjectId}"
        val credentialIssuer = cex.issuerMetadata.credentialIssuer
        val authDetails = AuthorizationDetails.fromOfferedCredential(offeredCred, credentialIssuer)
        val clientMetadata =
            OpenIDClientMetadata(customParameters = mapOf("authorization_endpoint" to JsonPrimitive(authEndpointUri)))
        val issuerState = cex.credentialOffer.grants[GrantType.authorization_code.value]?.issuerState
            ?: throw NoSuchElementException("Missing authorization_code.issuer_state")

        val authRequest = AuthorizationRequest(
            scope = setOf("openid"),
            clientId = cex.didInfo.did,
            state = cex.walletId,
            clientMetadata = clientMetadata,
            codeChallenge = codeChallenge,
            codeChallengeMethod = "S256",
            authorizationDetails = listOf(authDetails),
            redirectUri = authEndpointUri,
            issuerState = issuerState
        ).also {
            cex.authRequestCodeVerifier = codeVerifier
            cex.authRequest = it
        }

        return authRequest
    }

    private suspend fun resolveOfferedCredentials(ctx: FlowContext, offer: CredentialOffer): OfferedCredential {

        // Get issuer Metadata
        //
        val issuerMetadata = resolveOpenIDProviderMetadata(offer.credentialIssuer)
        log.info { "Issuer Metadata: ${Json.encodeToString(issuerMetadata)}" }

        val draft11Metadata = issuerMetadata as? OpenIDProviderMetadata.Draft11
            ?: throw IllegalStateException("Expected Draft11 metadata, but got ${issuerMetadata::class.simpleName}")

        // Resolve Offered Credential
        //
        val offeredCredentials = OpenID4VCI.resolveOfferedCredentials(offer, draft11Metadata)
        log.info { "Offered Credentials: ${Json.encodeToString(offeredCredentials)}" }
        if (offeredCredentials.size > 1) log.warn { "Multiple offered credentials, using first" }
        val offeredCredential = offeredCredentials.first()

        ctx.also {
            it.credentialOffer = offer
            it.offeredCredential = offeredCredential
            it.issuerMetadata = issuerMetadata
        }

        return offeredCredential
    }

    @OptIn(ExperimentalUuidApi::class)
    private suspend fun sendAuthorizationRequest(cex: FlowContext, authRequest: AuthorizationRequest): String {

        val authReqUrl = URLBuilder("${cex.authorizationEndpoint}/authorize").apply {
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
                    cex.putRequestObject(reqObjectId, authReq)

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

        log.info { "AuthorizationCode: ${cex.authCode}" }
        return cex.authCode
    }

    private suspend fun sendCredentialRequest(ctx: FlowContext, tokenResponse: TokenResponse): CredentialResponse {

        val accessToken = tokenResponse.accessToken
            ?: throw IllegalStateException("No accessToken")
        val cNonce = tokenResponse.cNonce
            ?: throw IllegalStateException("No c_nonce")

        val iat = Instant.now()
        val exp = iat.plusSeconds(300) // 5 mins expiry

        val kid = ctx.didInfo.authenticationId()

        val credReqHeader = JWSHeader.Builder(JWSAlgorithm.ES256)
            .type(JOSEObjectType("openid4vci-proof+jwt"))
            .keyID(kid)
            .build()

        val credentialTypes = ctx.offeredCredential.types
            ?: throw IllegalStateException("No credential types")

        val issuerUri = ctx.issuerMetadata.credentialIssuer
        val credentialEndpoint = ctx.issuerMetadata.credentialEndpoint
            ?: throw IllegalStateException("No credential_endpoint")

        val claimsBuilder = JWTClaimsSet.Builder()
            .issuer(ctx.didInfo.did)
            .audience(issuerUri)
            .issueTime(Date.from(iat))
            .expirationTime(Date.from(exp))
            .claim("nonce", cNonce)

        ctx.maybeAuthRequest?.state?.also {
            claimsBuilder.claim("state", it)
        }

        val credReqClaims = claimsBuilder.build()

        val signingInput = Json.encodeToString(createFlattenedJwsJson(credReqHeader, credReqClaims))
        val signedEncoded = widWalletSvc.signWithKey(ctx, kid, signingInput)
        val signedCredReqJwt = SignedJWT.parse(signedEncoded)
        log.info { "Credential Request Header: ${signedCredReqJwt.header}" }
        log.info { "Credential Request Claims: ${signedCredReqJwt.jwtClaimsSet}" }

        val credReqBody = Json.encodeToString(buildJsonObject {
            put("types", JsonArray(credentialTypes.map { JsonPrimitive(it) }))
            put("format", JsonPrimitive("jwt_vc"))
            put("proof", buildJsonObject {
                put("proof_type", JsonPrimitive("jwt"))
                put("jwt", JsonPrimitive(signedEncoded))
            })
        })

        log.info { "Send Credential Request: $credentialEndpoint" }
        log.info { "  $credReqBody" }

        val res = http.post(credentialEndpoint) {
            header(HttpHeaders.Authorization, "Bearer $accessToken")
            contentType(ContentType.Application.Json)
            setBody(credReqBody)
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

        ctx.credResponse = credRes
        return credRes
    }
}