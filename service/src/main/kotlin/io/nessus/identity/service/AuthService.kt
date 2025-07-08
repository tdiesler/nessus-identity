package io.nessus.identity.service

import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.util.JSONObjectUtils
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import id.walt.crypto.utils.JsonUtils.toJsonElement
import id.walt.oid4vc.OpenID4VCI
import id.walt.oid4vc.data.AuthorizationDetails
import id.walt.oid4vc.data.CredentialFormat
import id.walt.oid4vc.data.GrantDetails
import id.walt.oid4vc.data.dif.DescriptorMapping
import id.walt.oid4vc.data.dif.InputDescriptor
import id.walt.oid4vc.data.dif.InputDescriptorConstraints
import id.walt.oid4vc.data.dif.InputDescriptorField
import id.walt.oid4vc.data.dif.PresentationDefinition
import id.walt.oid4vc.data.dif.PresentationSubmission
import id.walt.oid4vc.data.dif.VCFormatDefinition
import id.walt.oid4vc.requests.AuthorizationRequest
import id.walt.oid4vc.requests.TokenRequest
import id.walt.oid4vc.responses.TokenResponse
import id.walt.w3c.utils.VCFormat
import io.github.oshai.kotlinlogging.KotlinLogging
import io.ktor.client.request.*
import io.ktor.client.request.forms.*
import io.ktor.client.statement.*
import io.ktor.http.*
import io.nessus.identity.api.AuthServiceApi
import io.nessus.identity.config.ConfigProvider.authEndpointUri
import io.nessus.identity.waltid.WaltidServiceProvider.widWalletSvc
import io.nessus.identity.waltid.authenticationId
import io.nessus.identity.waltid.publicKeyJwk
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import java.time.Instant
import java.util.Date
import kotlin.uuid.ExperimentalUuidApi
import kotlin.uuid.Uuid

// WalletService =======================================================================================================

object AuthService : AuthServiceApi {

    val log = KotlinLogging.logger {}

    override fun getAuthMetadataUrl(ctx: LoginContext): String {
        val metadataUrl = OpenID4VCI.getOpenIdProviderMetadataUrl("$authEndpointUri/${ctx.subjectId}")
        return metadataUrl
    }

    override fun getAuthMetadata(ctx: LoginContext): JsonObject {
        val metadata = buildAuthEndpointMetadata(ctx)
        return metadata
    }

    /**
     * Handle AuthorizationRequest from remote Holder to this Issuer's Auth Endpoint
     */
    override suspend fun handleAuthorizationRequest(cex: FlowContext, authReq: AuthorizationRequest): String {

        cex.authRequest = authReq
        cex.issuerMetadata = IssuerService.getIssuerMetadata(cex)

        // Validate the AuthorizationRequest
        //
        // [TODO] check VC types in authorization_details

        val isVPTokenRequest = authReq.scope.any { it.contains("vp_token") }
        if (isVPTokenRequest) {
            val redirectUrl = sendVPTokenRequest(cex, authReq)
            return redirectUrl
        } else {
            val redirectUrl = sendIDTokenRequest(cex, authReq)
            return redirectUrl
        }
    }

    override suspend fun handleIDTokenRequest(cex: FlowContext, queryParams: Map<String, List<String>>): String {

        // Verify required query params
        for (key in listOf("client_id", "nonce", "state", "redirect_uri", "request_uri", "response_type")) {
            queryParams[key] ?: throw IllegalStateException("Cannot find $key")
        }

        // The Wallet answers the ID Token Request by providing the id_token in the redirect_uri as instructed by response_mode of direct_post.
        // The id_token must be signed with the DID document's authentication key.

        val clientId = queryParams["client_id"]!!.first()
        val nonce = queryParams["nonce"]!!.first()
        val state = queryParams["state"]!!.first()
        val redirectUri = queryParams["redirect_uri"]!!.first()
        val requestUri = queryParams["request_uri"]!!.first()
        val responseType = queryParams["response_type"]!!.first()

        if (responseType != "id_token")
            throw IllegalStateException("Unexpected response_type: $responseType")

        log.info { "Trigger IDToken Request: $requestUri" }
        var res = http.get(requestUri)
        if (res.status != HttpStatusCode.OK)
            throw HttpStatusException(res.status, res.bodyAsText())

        val idTokenReq = res.bodyAsText()
        log.info { "IDToken Request: $idTokenReq" }

        val signedJWT = SignedJWT.parse(idTokenReq)
        log.info { "IDToken Request Header: ${signedJWT.header}" }
        log.info { "IDToken Request Claims: ${signedJWT.jwtClaimsSet}" }

        val iat = Instant.now()
        val exp = iat.plusSeconds(300) // 5 mins expiry

        val kid = cex.didInfo.authenticationId()

        val idTokenHeader = JWSHeader.Builder(JWSAlgorithm.ES256)
            .type(JOSEObjectType.JWT)
            .keyID(kid)
            .build()

        val idTokenClaims = JWTClaimsSet.Builder()
            .issuer(cex.didInfo.did)
            .subject(cex.didInfo.did)
            .audience(clientId)
            .issueTime(Date.from(iat))
            .expirationTime(Date.from(exp))
            .claim("nonce", nonce)
            .claim("state", state)
            .build()

        val idTokenJwt = SignedJWT(idTokenHeader, idTokenClaims)
        log.info { "IDToken Header: ${idTokenJwt.header}" }
        log.info { "IDToken Claims: ${idTokenJwt.jwtClaimsSet}" }

        val signingInput = Json.encodeToString(createFlattenedJwsJson(idTokenHeader, idTokenClaims))
        val signedEncoded = widWalletSvc.signWithKey(kid, signingInput)

        log.info { "IDToken: $signedEncoded" }
        if (!verifyJwt(SignedJWT.parse(signedEncoded), cex.didInfo))
            throw IllegalStateException("IDToken signature verification failed")

        // Send IDToken  -----------------------------------------------------------------------------------------------
        //

        log.info { "Send IDToken: $redirectUri" }
        val formData = mapOf(
            "id_token" to signedEncoded,
            "state" to state,
        ).also {
            it.forEach { (k, v) -> log.info { "  $k=$v" } }
        }

        res = http.post(redirectUri) {
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
            cex.authCode = it
        } ?: throw IllegalStateException("No authorization code")

        return authCode
    }

    @OptIn(ExperimentalUuidApi::class)
    fun handleIDTokenResponse(cex: FlowContext, postParams: Map<String, List<String>>): String {

        val idToken = postParams["id_token"]?.firstOrNull()
            ?: throw IllegalStateException("No id_token")

        val idTokenJwt = SignedJWT.parse(idToken)
        log.info { "IDToken Header: ${idTokenJwt.header}" }
        log.info { "IDToken Claims: ${idTokenJwt.jwtClaimsSet}" }

        // [TODO] validate IDToken

        cex.authCode = "${Uuid.random()}"

        val authReq = cex.authRequest
        val idTokenRedirect = URLBuilder("${authReq.redirectUri}").apply {
            parameters.append("code", cex.authCode)
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

    @OptIn(ExperimentalUuidApi::class)
    fun handleVPTokenResponse(cex: FlowContext, postParams: Map<String, List<String>>): String {

        val vpToken = postParams["vp_token"]?.firstOrNull()
            ?: throw IllegalStateException("No vp_token")

        val vpTokenJwt = SignedJWT.parse(vpToken)
        log.info { "VPToken Header: ${vpTokenJwt.header}" }
        log.info { "VPToken Claims: ${vpTokenJwt.jwtClaimsSet}" }

        // Validate VPToken
        //
        val vpClaims = vpTokenJwt.jwtClaimsSet
        vpClaims.expirationTime?.also {
            if (it.before(Date())) {
                throw IllegalStateException("Token has expired on: $it")
            }
        }
        vpClaims.notBeforeTime?.also {
            if (Date().before(it)) {
                throw IllegalStateException("Token cannot be used before: $it")
            }
        }

        val authReq = cex.authRequest
        val urlBuilder = URLBuilder("${authReq.redirectUri}")

        val vcArray = vpClaims.getClaim("vp")
            .toJsonElement()
            .jsonObject["verifiableCredential"]
            ?.jsonArray

        // Validate Credentials
        //
        var validationError: Throwable? = null
        log.info { "VPToken VerifiableCredentials" }
        vcArray?.map { it.jsonPrimitive.content }?.forEach { vcEncoded ->
            val vcJwt = SignedJWT.parse(vcEncoded)
            log.info { "VC Encoded: $vcEncoded" }
            log.info { "   Header: ${vcJwt.header}" }
            log.info { "   Claims: ${vcJwt.jwtClaimsSet}" }
            runCatching {
                validateVerifiableCredential(vcJwt)
            }.onFailure {
                validationError = it
                urlBuilder.apply {
                    parameters.append("error", "invalid_request")
                    parameters.append("error_description", "${validationError.message}")
                }
            }
        }

        if (validationError == null) {
            cex.authCode = "${Uuid.random()}"
            urlBuilder.parameters.append("code", cex.authCode)
        }
        if (authReq.state != null) {
            urlBuilder.parameters.append("state", "${authReq.state}")
        }

        val redirectUrl = urlBuilder.buildString()
        log.info { "VPToken Response $redirectUrl" }
        urlQueryToMap(redirectUrl).also {
            it.forEach { (k, v) -> log.info { "  $k=$v" } }
        }
        return redirectUrl
    }

    @OptIn(ExperimentalUuidApi::class)
    override suspend fun handleVPTokenRequest(cex: FlowContext, queryParams: Map<String, List<String>>): String {

        // Verify required query params
        for (key in listOf("client_id", "request_uri", "response_type")) {
            queryParams[key] ?: throw IllegalStateException("Cannot find $key")
        }

        val clientId = queryParams["client_id"]!!.first()
        val requestUri = queryParams["request_uri"]!!.first()
        val responseType = queryParams["response_type"]!!.first()

        if (responseType != "vp_token")
            throw IllegalStateException("Unexpected response_type: $responseType")

        if (!requestUri.startsWith(authEndpointUri))
            throw IllegalStateException("Unexpected request_uri: $requestUri")

        val queryParams = urlQueryToMap(requestUri)
        val reqObjectId = queryParams["request_object"]
        if (reqObjectId == null)
            throw IllegalStateException("No request_object in: $requestUri")

        val reqObject = cex.getRequestObject(reqObjectId) as? AuthorizationRequest
            ?: throw IllegalStateException("No request_object for: $reqObjectId")

        log.info { "VPToken Request: ${Json.encodeToString(reqObject)}" }

        val nonce = reqObject.nonce
            ?: throw IllegalStateException("No nonce in: $reqObject")

        val state = reqObject.state
            ?: throw IllegalStateException("No state in: $reqObject")

        val redirectUri = reqObject.redirectUri
            ?: throw IllegalStateException("No redirectUri in: $reqObject")

        val vpdef = reqObject.presentationDefinition
            ?: throw IllegalStateException("No presentationDefinition in: $reqObject")

        val jti = "${Uuid.random()}"
        val iat = Instant.now()
        val exp = iat.plusSeconds(300) // 5 mins expiry

        val kid = cex.didInfo.authenticationId()
        val vpTokenHeader = JWSHeader.Builder(JWSAlgorithm.ES256)
            .type(JOSEObjectType.JWT)
            .keyID(kid)
            .build()

        val vpJson = """{
            "@context": [ "https://www.w3.org/2018/credentials/v1" ],
            "id": "$jti",
            "type": [ "VerifiablePresentation" ],
            "holder": "${cex.didInfo.did}",
            "verifiableCredential": []
        }"""
        val vpObj = JSONObjectUtils.parse(vpJson)

        @Suppress("UNCHECKED_CAST")
        val vcArray = vpObj["verifiableCredential"] as MutableList<String>

        val descriptorMap = mutableListOf<DescriptorMapping>()
        val vpSubmission = PresentationSubmission(
            id = "${Uuid.random()}",
            definitionId = vpdef.id,
            descriptorMap = descriptorMap
        )

        val matchingCredentials = widWalletSvc.findCredentials(vpdef).toMap()

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

            descriptorMap.add(dm)
            vcArray.add(wc.document)
        }

        val vpSubmissionJson = Json.encodeToString(vpSubmission)

        val vpTokenClaims = JWTClaimsSet.Builder()
            .jwtID(jti)
            .issuer(cex.didInfo.did)
            .subject(cex.didInfo.did)
            .audience(clientId)
            .issueTime(Date.from(iat))
            .notBeforeTime(Date.from(iat))
            .expirationTime(Date.from(exp))
            .claim("nonce", nonce)
            .claim("state", state)
            .claim("vp", vpObj)
            .build()

        val vpTokenJwt = SignedJWT(vpTokenHeader, vpTokenClaims)
        log.info { "VPToken Header: ${vpTokenJwt.header}" }
        log.info { "VPToken Claims: ${vpTokenJwt.jwtClaimsSet}" }

        val signingInput = Json.encodeToString(createFlattenedJwsJson(vpTokenHeader, vpTokenClaims))
        val signedEncoded = widWalletSvc.signWithKey(kid, signingInput)

        log.info { "VPToken: $signedEncoded" }
        if (!verifyJwt(SignedJWT.parse(signedEncoded), cex.didInfo))
            throw IllegalStateException("VPToken signature verification failed")

        // Send VPToken  -----------------------------------------------------------------------------------------------
        //

        log.info { "Send VPToken: $redirectUri" }
        val formData = mapOf(
            "vp_token" to signedEncoded,
            "presentation_submission" to vpSubmissionJson,
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
            cex.authCode = it
        } ?: throw IllegalStateException("No authorization code")

        return authCode
    }

    @OptIn(ExperimentalUuidApi::class)
    suspend fun handleTokenRequestAuthCode(
        cex: FlowContext,
        tokReq: TokenRequest.AuthorizationCode
    ): TokenResponse {

        val grantType = tokReq.grantType
        val codeVerifier = tokReq.codeVerifier
        val redirectUri = tokReq.redirectUri
        val code = tokReq.code

        // Verify token request
        //
        if (tokReq.clientId != cex.authRequest.clientId)
            throw IllegalArgumentException("Invalid client_id: ${tokReq.clientId}")

        // [TODO] verify token request code challenge

        val tokenResponse = buildTokenResponse(cex)
        return tokenResponse
    }

    suspend fun handleTokenRequestPreAuthorized(
        cex: FlowContext,
        tokReq: TokenRequest.PreAuthorizedCode
    ): TokenResponse {

        // [TODO] Externalize pre-authorization code mapping
        val ebsiClientId =
            "did:key:z2dmzD81cgPx8Vki7JbuuMmFYrWPgYoytykUZ3eyqht1j9Kboj7g9PfXJxbbs4KYegyr7ELnFVnpDMzbJJDDNZjavX6jvtDmALMbXAGW67pdTgFea2FrGGSFs8Ejxi96oFLGHcL4P6bjLDPBJEvRRHSrG4LsPne52fczt2MWjHLLJBvhAC"
        val preAuthorisedCodeToClientId = mapOf(
            "CTWalletSamePreAuthorisedInTime" to AuthorizationRequest(
                clientId = ebsiClientId,
                authorizationDetails = listOf(
                    AuthorizationDetails(
                        format = CredentialFormat.jwt_vc,
                        types = listOf(
                            "VerifiableCredential",
                            "VerifiableAttestation",
                            "CTWalletSamePreAuthorisedInTime"
                        )
                    )
                )
            ),
            "CTWalletSamePreAuthorisedDeferred" to AuthorizationRequest(
                clientId = ebsiClientId,
                authorizationDetails = listOf(
                    AuthorizationDetails(
                        format = CredentialFormat.jwt_vc,
                        types = listOf(
                            "VerifiableCredential",
                            "VerifiableAttestation",
                            "CTWalletSamePreAuthorisedDeferred"
                        )
                    )
                )
            ),
        )

        cex.issuerMetadata = IssuerService.getIssuerMetadata(cex)
        cex.authRequest = preAuthorisedCodeToClientId[tokReq.preAuthorizedCode]
            ?: throw IllegalStateException("No client_id mapping for: ${tokReq.preAuthorizedCode}")

        val tokenResponse = buildTokenResponse(cex)
        return tokenResponse
    }

    override suspend fun sendTokenRequestAuthCode(cex: FlowContext, authCode: String): TokenResponse {

        val tokenReqUrl = "${cex.authorizationEndpoint}/token"

        val tokenRequest = TokenRequest.AuthorizationCode(
            clientId = cex.didInfo.did,
            redirectUri = cex.authRequest.redirectUri,
            codeVerifier = cex.authRequestCodeVerifier,
            code = authCode,
        )
        val formData = tokenRequest.toHttpParameters()

        log.info { "Send Token Request $tokenReqUrl" }
        log.info { "  $tokenRequest" } // AuthorizationCode is not @Serializable

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

        val tokenResponse = TokenResponse.fromJSONString(tokenResponseJson).also {
            cex.accessToken = SignedJWT.parse(it.accessToken)
        }
        return tokenResponse
    }

    override suspend fun sendTokenRequestPreAuthorized(cex: FlowContext, grant: GrantDetails): TokenResponse {

        val tokenReqUrl = "${cex.authorizationEndpoint}/token"

        val tokenRequest = TokenRequest.PreAuthorizedCode(
            preAuthorizedCode = grant.preAuthorizedCode as String,
            userPIN = UserPinHolder.getUserPin()
        )
        val formData = tokenRequest.toHttpParameters()

        log.info { "Send Token Request $tokenReqUrl" }
        formData.forEach { (k, lst) -> lst.forEach { v -> log.info { "  $k=$v" }}}

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

        val tokenResponse = TokenResponse.fromJSONString(tokenResponseJson).also {
            cex.accessToken = SignedJWT.parse(it.accessToken)
        }
        return tokenResponse
    }

    // Private ---------------------------------------------------------------------------------------------------------

    @OptIn(ExperimentalUuidApi::class)
    private suspend fun buildTokenResponse(cex: FlowContext): TokenResponse {
        val keyJwk = cex.didInfo.publicKeyJwk()
        val kid = keyJwk["kid"]?.jsonPrimitive?.content as String

        val iat = Instant.now()
        val expiresIn: Long = 86400
        val exp = iat.plusSeconds(expiresIn)

        val nonce = "${Uuid.random()}"

        val tokenHeader = JWSHeader.Builder(JWSAlgorithm.ES256)
            .type(JOSEObjectType.JWT)
            .keyID(kid)
            .build()

        val claimsBuilder = JWTClaimsSet.Builder()
            .issuer(cex.issuerMetadata.credentialIssuer)
            .issueTime(Date.from(iat))
            .expirationTime(Date.from(exp))
            .claim("nonce", nonce)

        cex.maybeAuthRequest?.clientId?.also {
            claimsBuilder.subject(it)
        }
        cex.maybeAuthRequest?.authorizationDetails?.also {
            val authorizationDetails: List<JsonObject> = it.map { ad -> ad.toJSON() }
            claimsBuilder.claim("authorization_details", authorizationDetails)
        }
        val tokenClaims = claimsBuilder.build()

        val rawTokenJwt = SignedJWT(tokenHeader, tokenClaims)
        log.info { "Token Header: ${rawTokenJwt.header}" }
        log.info { "Token Claims: ${rawTokenJwt.jwtClaimsSet}" }

        val signingInput = Json.encodeToString(createFlattenedJwsJson(tokenHeader, tokenClaims))
        val signedEncoded = widWalletSvc.signWithKey(kid, signingInput)
        val accessToken = SignedJWT.parse(signedEncoded)

        if (!verifyJwt(accessToken, cex.didInfo))
            throw IllegalStateException("AccessToken signature verification failed")

        val tokenRespJson = """
            {
              "access_token": "$signedEncoded",
              "token_type": "bearer",
              "expires_in": $expiresIn,
              "c_nonce": "$nonce",
              "c_nonce_expires_in": $expiresIn
            }            
        """.trimIndent()

        val tokenResponse = TokenResponse.fromJSONString(tokenRespJson).also {
            cex.accessToken = accessToken
        }
        log.info { "Token Response: ${Json.encodeToString(tokenResponse)}" }
        return tokenResponse
    }

    private fun buildAuthEndpointMetadata(ctx: LoginContext): JsonObject {
        val baseUrl = "$authEndpointUri/${ctx.subjectId}"
        return Json.parseToJsonElement(
            """
            {
              "authorization_endpoint": "$baseUrl/authorize",
              "grant_types_supported": [
                "authorization_code"
              ],
              "id_token_signing_alg_values_supported": [
                "ES256"
              ],
              "id_token_types_supported": [
                "subject_signed_id_token",
                "attester_signed_id_token"
              ],
              "issuer": "$baseUrl",
              "jwks_uri": "$baseUrl/jwks",
              "redirect_uris": [
                "$baseUrl/direct_post"
              ],
              "request_authentication_methods_supported": {
                "authorization_endpoint": [
                  "request_object"
                ]
              },
              "request_object_signing_alg_values_supported": [
                "ES256"
              ],
              "request_parameter_supported": true,
              "request_uri_parameter_supported": true,
              "response_modes_supported": [
                "query"
              ],
              "response_types_supported": [
                "code",
                "vp_token",
                "id_token"
              ],
              "scopes_supported": [
                "openid"
              ],
              "subject_syntax_types_discriminations": [
                "did:key:jwk_jcs-pub",
                "did:ebsi:v1"
              ],
              "subject_syntax_types_supported": [
                "did:key",
                "did:ebsi"
              ],
              "subject_trust_frameworks_supported": [
                "ebsi"
              ],
              "subject_types_supported": [
                "public"
              ],
              "token_endpoint": "$baseUrl/token",
              "token_endpoint_auth_methods_supported": [
                "private_key_jwt"
              ],
              "vp_formats_supported": {
                "jwt_vc": {
                  "alg_values_supported": [
                    "ES256"
                  ]
                },
                "jwt_vc_json": {
                  "alg_values_supported": [
                    "ES256"
                  ]
                },
                "jwt_vp": {
                  "alg_values_supported": [
                    "ES256"
                  ]
                },
                "jwt_vp_json": {
                  "alg_values_supported": [
                    "ES256"
                  ]
                }
              }
            }            
        """.trimIndent()
        ).jsonObject
    }

    /**
     * Send ID Token request currently from Issuer's Auth Endpoint to Holder Wallet
     *
     * The Issuer's Authorisation Server validates the request and proceeds by requesting authentication of a DID from the client.
     * The ID Token Request also serves as an Authorisation Request and MUST be a signed Request Object.
     *
     * @return The wanted redirect url
     */
    private suspend fun sendIDTokenRequest(cex: FlowContext, authReq: AuthorizationRequest): String {

        val issuerMetadata = cex.issuerMetadata
        val authorizationEndpoint = cex.authorizationEndpoint

        val keyJwk = cex.didInfo.publicKeyJwk()
        val kid = keyJwk["kid"]?.jsonPrimitive?.content as String

        val iat = Instant.now()
        val exp = iat.plusSeconds(300) // 5 mins expiry

        val idTokenHeader = JWSHeader.Builder(JWSAlgorithm.ES256)
            .type(JOSEObjectType.JWT)
            .keyID(kid)
            .build()

        @OptIn(ExperimentalUuidApi::class)
        val idTokenClaims = JWTClaimsSet.Builder()
            .issuer(issuerMetadata.credentialIssuer)
            .audience(authReq.clientId)
            .issueTime(Date.from(iat))
            .expirationTime(Date.from(exp))
            .claim("response_type", "id_token")
            .claim("response_mode", "direct_post")
            .claim("client_id", issuerMetadata.credentialIssuer)
            .claim("redirect_uri", "$authorizationEndpoint/direct_post")
            .claim("scope", "openid")
            .claim("nonce", "${Uuid.random()}")
            .build()

        val idTokenJwt = SignedJWT(idTokenHeader, idTokenClaims)
        log.info { "IDToken Request Header: ${idTokenJwt.header}" }
        log.info { "IDToken Request Claims: ${idTokenJwt.jwtClaimsSet}" }

        val signingInput = Json.encodeToString(createFlattenedJwsJson(idTokenHeader, idTokenClaims))
        val signedEncoded = widWalletSvc.signWithKey(kid, signingInput)

        val idTokenRedirectUrl = URLBuilder("${authReq.redirectUri}").apply {
            parameters.append("client_id", authorizationEndpoint)
            parameters.append("response_type", "id_token")
            parameters.append("response_mode", "direct_post")
            parameters.append("scope", "openid")
            parameters.append("redirect_uri", "$authorizationEndpoint/direct_post")
            parameters.append("request", signedEncoded)
        }.buildString()

        log.info { "IDToken Request $idTokenRedirectUrl" }
        urlQueryToMap(idTokenRedirectUrl).also {
            it.forEach { (k, v) -> log.info { "  $k=$v" } }
        }

        return idTokenRedirectUrl
    }

    @OptIn(ExperimentalUuidApi::class)
    private suspend fun sendVPTokenRequest(cex: FlowContext, authReq: AuthorizationRequest): String {

        val issuerMetadata = cex.issuerMetadata
        val authorizationEndpoint = cex.authorizationEndpoint

        val keyJwk = cex.didInfo.publicKeyJwk()
        val kid = keyJwk["kid"]?.jsonPrimitive?.content as String

        val iat = Instant.now()
        val exp = iat.plusSeconds(300) // 5 mins expiry
        val scopes = authReq.scope.joinToString(" ")

        val vpTokenHeader = JWSHeader.Builder(JWSAlgorithm.ES256)
            .type(JOSEObjectType.JWT)
            .keyID(kid)
            .build()

        fun buildInputDescriptor(): InputDescriptor {
            return InputDescriptor(
                id = "${Uuid.random()}",
                format = mapOf(VCFormat.jwt_vc to VCFormatDefinition(alg = setOf("ES256"))),
                constraints = InputDescriptorConstraints(
                    fields = listOf(
                        InputDescriptorField(
                            path = listOf("$.vc.type"),
                            filter = Json.parseToJsonElement(
                                """{
                                "type": "array",
                                "contains": { "const": "VerifiableAttestation" }
                            }""".trimIndent()
                            ).jsonObject
                        )
                    ),
                ),
            )
        }

        val presentationDefinition = PresentationDefinition(
            format = mapOf(
                VCFormat.jwt_vc to VCFormatDefinition(alg = setOf("ES256")),
                VCFormat.jwt_vp to VCFormatDefinition(alg = setOf("ES256"))
            ),
            inputDescriptors = listOf(
                buildInputDescriptor(),
                buildInputDescriptor(),
                buildInputDescriptor(),
            ),
        ).toJSON()

        val presentationDefinitionJson = Json.encodeToString(presentationDefinition)
        log.info { "PresentationDefinition: $presentationDefinitionJson" }

        @OptIn(ExperimentalUuidApi::class)
        val vpTokenClaims = JWTClaimsSet.Builder()
            .issuer(issuerMetadata.credentialIssuer)
            .audience(authReq.clientId)
            .issueTime(Date.from(iat))
            .expirationTime(Date.from(exp))
            .claim("response_type", "vp_token")
            .claim("response_mode", "direct_post")
            .claim("client_id", issuerMetadata.credentialIssuer)
            .claim("redirect_uri", "$authorizationEndpoint/direct_post")
            .claim("scope", scopes)
            .claim("nonce", "${Uuid.random()}")
            .claim("presentation_definition", JSONObjectUtils.parse(presentationDefinitionJson))
            .build()

        val idTokenJwt = SignedJWT(vpTokenHeader, vpTokenClaims)
        log.info { "VPToken Request Header: ${idTokenJwt.header}" }
        log.info { "VPToken Request Claims: ${idTokenJwt.jwtClaimsSet}" }

        val signingInput = Json.encodeToString(createFlattenedJwsJson(vpTokenHeader, vpTokenClaims))
        val signedEncoded = widWalletSvc.signWithKey(kid, signingInput)

        val vpTokenRedirectUrl = URLBuilder("${authReq.redirectUri}").apply {
            parameters.append("client_id", authorizationEndpoint)
            parameters.append("response_type", "vp_token")
            parameters.append("response_mode", "direct_post")
            parameters.append("scope", scopes)
            parameters.append("redirect_uri", "$authorizationEndpoint/direct_post")
            parameters.append("request", signedEncoded)
        }.buildString()

        log.info { "VPToken Request $vpTokenRedirectUrl" }
        urlQueryToMap(vpTokenRedirectUrl).also {
            it.forEach { (k, v) -> log.info { "  $k=$v" } }
        }

        return vpTokenRedirectUrl
    }

    private fun validateVerifiableCredential(vcJwt: SignedJWT) {

        val claims = vcJwt.jwtClaimsSet
        val id = claims.getClaim("vc").toJsonElement()
            .jsonObject["id"]?.jsonPrimitive?.content ?: throw IllegalArgumentException("No vc.id in: $claims")
        val credentialStatus = claims.getClaim("vc").toJsonElement()
            .jsonObject["credentialStatus"]?.jsonObject

        credentialStatus?.also {
            val statusPurpose = it["statusPurpose"]?.jsonPrimitive?.content
            if (statusPurpose == "revocation")
                throw VerificationException(id, "VC '$id' is revoked")
        }

        claims.expirationTime?.also {
            if (it.before(Date()))
                throw VerificationException(id, "VC '$id' is expired")
        }

        claims.notBeforeTime?.also {
            if (Date().before(it))
                throw VerificationException(id, "VC '$id' is not yet valid")
        }
    }
}