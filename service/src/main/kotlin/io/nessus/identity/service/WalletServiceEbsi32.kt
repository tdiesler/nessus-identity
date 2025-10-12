package io.nessus.identity.service

import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.util.Base64URL
import com.nimbusds.jose.util.JSONObjectUtils
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import id.walt.oid4vc.OpenID4VCI
import id.walt.oid4vc.data.CredentialFormat
import id.walt.oid4vc.data.dif.DescriptorMapping
import id.walt.oid4vc.data.dif.PresentationSubmission
import id.walt.oid4vc.requests.AuthorizationRequest
import id.walt.oid4vc.requests.CredentialRequest
import id.walt.oid4vc.requests.TokenRequest
import id.walt.oid4vc.responses.CredentialResponse
import id.walt.oid4vc.responses.TokenResponse
import id.walt.w3c.utils.VCFormat
import io.ktor.client.*
import io.ktor.client.plugins.contentnegotiation.*
import io.ktor.client.request.*
import io.ktor.client.request.forms.*
import io.ktor.client.statement.*
import io.ktor.http.*
import io.ktor.serialization.kotlinx.json.*
import io.nessus.identity.extend.signWithKey
import io.nessus.identity.extend.toSignedJWT
import io.nessus.identity.extend.verifyJwtSignature
import io.nessus.identity.service.AttachmentKeys.ACCESS_TOKEN_ATTACHMENT_KEY
import io.nessus.identity.service.AttachmentKeys.AUTH_CODE_ATTACHMENT_KEY
import io.nessus.identity.service.AttachmentKeys.AUTH_REQUEST_ATTACHMENT_KEY
import io.nessus.identity.service.AttachmentKeys.AUTH_REQUEST_CODE_VERIFIER_ATTACHMENT_KEY
import io.nessus.identity.service.AttachmentKeys.PRESENTATION_SUBMISSION_ATTACHMENT_KEY
import io.nessus.identity.service.AttachmentKeys.REQUEST_URI_OBJECT_ATTACHMENT_KEY
import io.nessus.identity.service.AuthServiceEbsi32.Companion.authEndpointUri
import io.nessus.identity.service.CredentialOfferRegistry.assertCredentialOfferRecord
import io.nessus.identity.types.AuthorizationRequestBuilder
import io.nessus.identity.types.CredentialOffer
import io.nessus.identity.types.CredentialOfferDraft11
import io.nessus.identity.types.IssuerMetadataDraft11
import io.nessus.identity.types.VCDataV11Jwt
import io.nessus.identity.waltid.WaltIDServiceProvider.widWalletSvc
import io.nessus.identity.waltid.authenticationId
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import java.time.Instant
import java.util.*
import kotlin.random.Random
import kotlin.uuid.Uuid

// WalletServiceEbsi32 ================================================================================================

class WalletServiceEbsi32() : AbstractWalletService<CredentialOfferDraft11>() {

    fun addCredential(
        ctx: OIDContext,
        credRes: CredentialResponse,
    ) {
        val walletId = ctx.walletId
        val credJwt = credRes.toSignedJWT()
        val format = credRes.format as CredentialFormat

        // Verify that we can unmarshall the credential
        Json.decodeFromString<VCDataV11Jwt>("${credJwt.payload}")

        widWalletSvc.addCredential(walletId, format, credJwt)
    }

    suspend fun createCredentialRequest(
        ctx: OIDContext,
        types: List<String>,
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

        val credReqJson = Json.encodeToString(buildJsonObject {
            put("types", JsonArray(types.map { JsonPrimitive(it) }))
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

    suspend fun createIDToken(
        ctx: OIDContext,
        reqParams: Map<String, String>
    ): SignedJWT {

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
        idTokenJwt.verifyJwtSignature("IDToken", ctx.didInfo)

        return idTokenJwt
    }

    suspend fun createVPToken(
        ctx: OIDContext,
        authReq: AuthorizationRequest
    ): SignedJWT {

        log.info { "VPToken AuthorizationRequest: ${Json.encodeToString(authReq)}" }

        val clientId = authReq.clientId
        val nonce = authReq.nonce
        val state = authReq.state

        val vpdef = authReq.presentationDefinition
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
        val matchingCredentials = widWalletSvc.findCredentialsByPresentationDefinition(ctx, vpdef).toMap()
        val matchingCredentialsByInputDescriptorId = matchingCredentials.entries.associate { (ind, wc) -> ind.id to wc }

        for (ind in vpdef.inputDescriptors) {

            val wc = matchingCredentialsByInputDescriptorId[ind.id]
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

        nonce?.also { claimsBuilder.claim("nonce", it) }
        state?.also { claimsBuilder.claim("state", it) }
        val vpTokenClaims = claimsBuilder.build()

        val vpTokenJwt = SignedJWT(vpTokenHeader, vpTokenClaims).signWithKey(ctx, kid)
        log.info { "VPToken Header: ${vpTokenJwt.header}" }
        log.info { "VPToken Claims: ${vpTokenJwt.jwtClaimsSet}" }

        val vpToken = vpTokenJwt.serialize()
        log.info { "VPToken: $vpToken" }

        vpTokenJwt.verifyJwtSignature("VPToken", ctx.didInfo)

        ctx.putAttachment(PRESENTATION_SUBMISSION_ATTACHMENT_KEY, vpSubmission)
        return vpTokenJwt
    }

    fun createTokenRequestAuthCode(
        ctx: OIDContext,
        authCode: String
    ): TokenRequest {

        val tokenRequest = TokenRequest.AuthorizationCode(
            clientId = ctx.did,
            redirectUri = ctx.authRequest.redirectUri,
            codeVerifier = ctx.authRequestCodeVerifier,
            code = authCode,
        )
        return tokenRequest
    }

    fun createTokenRequestPreAuthorized(
        ctx: OIDContext,
        credOffer: CredentialOfferDraft11,
        userPin: String
    ): TokenRequest {

        val preAuthCode = credOffer.getPreAuthorizedCodeGrant()?.preAuthorizedCode
            ?: throw IllegalStateException("No pre-authorized code")

        val tokenRequest = TokenRequest.PreAuthorizedCode(
            clientId = ctx.did,
            preAuthorizedCode = preAuthCode,
            userPIN = userPin
        )

        // [TODO #247] TokenRequest not serializable to json
        // https://github.com/tdiesler/nessus-identity/issues/247
        log.info { "TokenRequest: $tokenRequest" }
        return tokenRequest
    }

    suspend fun getCredentialOfferFromUri(offerUri: String): CredentialOfferDraft11 {
        val waltidOffer = OpenID4VCI.parseAndResolveCredentialOfferRequestUrl(offerUri)
        val credOffer = CredentialOffer.fromJson(waltidOffer.toJSON())
        log.info { "CredentialOffer: ${credOffer.toJson()}" }
        return credOffer as CredentialOfferDraft11
    }

    suspend fun getCredentialFromOffer(
        ctx: OIDContext,
        credOffer: CredentialOfferDraft11
    ): CredentialResponse {

        ctx.credentialOffer = credOffer
        ctx.issuerMetadata = credOffer.resolveIssuerMetadata()

        val accessToken = credOffer.getPreAuthorizedCodeGrant()?.let {
            val authCode = it.preAuthorizedCode
            val userPin = assertCredentialOfferRecord(authCode).userPin as String
            val tokenRequest = createTokenRequestPreAuthorized(ctx, credOffer, userPin)
            sendTokenRequestPreAuthorized(ctx, tokenRequest)
        } ?: run {
            val rndBytes = Random.nextBytes(32)
            val codeVerifier = Base64URL.encode(rndBytes).toString()
            val redirectUri = "$authEndpointUri/${ctx.targetId}"
            val authRequest = AuthorizationRequestBuilder()
                .withClientId(ctx.did)
                .withClientState(ctx.walletId)
                .withCodeChallengeMethod("S256")
                .withCodeVerifier(codeVerifier)
                .withIssuerMetadata(ctx.issuerMetadata)
                .withRedirectUri(redirectUri)
                .buildFrom(credOffer)
            ctx.putAttachment(AUTH_REQUEST_ATTACHMENT_KEY, authRequest)
            ctx.putAttachment(AUTH_REQUEST_CODE_VERIFIER_ATTACHMENT_KEY, codeVerifier)
            val authCode = sendAuthorizationRequest(ctx, authRequest)
            val tokenReq = createTokenRequestAuthCode(ctx, authCode)
            sendTokenRequestAuthCode(ctx, tokenReq)
        }

        val types = credOffer.getTypes()
        val credReq = createCredentialRequest(ctx, types, accessToken)
        val credRes = sendCredentialRequest(ctx, credReq)

        return credRes
    }

    suspend fun getDeferredCredential(
        ctx: OIDContext,
        acceptanceToken: String
    ): CredentialResponse {

        val metadata = ctx.issuerMetadata as IssuerMetadataDraft11
        val deferredCredentialEndpoint = metadata.deferredCredentialEndpoint
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

    suspend fun sendAuthorizationRequest(
        ctx: OIDContext,
        authRequest: AuthorizationRequest
    ): String {

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

    suspend fun sendCredentialRequest(
        ctx: OIDContext,
        credReq: CredentialRequest
    ): CredentialResponse {

        val accessToken = ctx.accessToken
        val credentialEndpoint = ctx.issuerMetadata.credentialEndpoint

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

    suspend fun sendIDToken(
        ctx: OIDContext,
        redirectUri: String,
        idTokenJwt: SignedJWT
    ): String {

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

    suspend fun sendVPToken(
        ctx: OIDContext,
        vpTokenJwt: SignedJWT
    ): String {

        val reqObject = ctx.assertAttachment(REQUEST_URI_OBJECT_ATTACHMENT_KEY) as AuthorizationRequest
        val vpSubmission = ctx.assertAttachment(PRESENTATION_SUBMISSION_ATTACHMENT_KEY, true)

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

    suspend fun sendTokenRequestAuthCode(
        ctx: OIDContext,
        tokenReq: TokenRequest
    ): TokenResponse {

        val tokenReqUrl = "${ctx.authorizationServer}/token"

        log.info { "Send Token Request $tokenReqUrl" }
        log.info { "  $tokenReq" } // AuthorizationCode is not @Serializable

        val formData = tokenReq.toHttpParameters()
        val res = http.post(tokenReqUrl) {
            contentType(ContentType.Application.FormUrlEncoded)
            setBody(FormDataContent(Parameters.build {
                formData.forEach { (k, lst) -> lst.forEach { v -> append(k, v) } }
            }))
        }

        if (res.status != HttpStatusCode.OK)
            throw HttpStatusException(res.status, res.bodyAsText())

        val tokenResponseJson = res.bodyAsText()
        log.info { "Token Response: $tokenResponseJson" }
        val tokenRes = TokenResponse.fromJSONString(tokenResponseJson)

        val accessTokenJwt = SignedJWT.parse(tokenRes.accessToken)
        ctx.putAttachment(ACCESS_TOKEN_ATTACHMENT_KEY, accessTokenJwt)

        return tokenRes
    }

    suspend fun sendTokenRequestPreAuthorized(
        ctx: OIDContext,
        tokenRequest: TokenRequest
    ): TokenResponse {

        val tokenReqUrl = "${ctx.authorizationServer}/token"
        val formData = tokenRequest.toHttpParameters()

        log.info { "Send TokenRequest $tokenReqUrl" }
        formData.forEach { (k, lst) -> lst.forEach { v -> log.info { "  $k=$v" } } }

        val res = http.post(tokenReqUrl) {
            contentType(ContentType.Application.FormUrlEncoded)
            setBody(FormDataContent(Parameters.build {
                formData.forEach { (k, lst) -> lst.forEach { v -> append(k, v) } }
            }))
        }

        if (res.status != HttpStatusCode.OK)
            throw HttpStatusException(res.status, res.bodyAsText())

        val tokenResponseJson = res.bodyAsText()
        log.info { "Token Response: $tokenResponseJson" }
        val tokenRes = TokenResponse.fromJSONString(tokenResponseJson)

        val accessToken = SignedJWT.parse(tokenRes.accessToken)
        ctx.putAttachment(ACCESS_TOKEN_ATTACHMENT_KEY, accessToken)

        return tokenRes
    }

    // Private ---------------------------------------------------------------------------------------------------------
}