package io.nessus.identity.service

import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.util.JSONObjectUtils
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import id.walt.oid4vc.data.AuthorizationDetails
import id.walt.oid4vc.data.CredentialFormat
import id.walt.oid4vc.data.dif.DescriptorMapping
import id.walt.oid4vc.data.dif.InputDescriptor
import id.walt.oid4vc.data.dif.PresentationDefinition
import id.walt.oid4vc.data.dif.PresentationSubmission
import id.walt.w3c.utils.VCFormat
import id.walt.webwallet.db.models.WalletCredential
import io.github.oshai.kotlinlogging.KotlinLogging
import io.ktor.client.request.*
import io.ktor.client.request.forms.*
import io.ktor.client.statement.*
import io.ktor.http.*
import io.nessus.identity.AuthorizationContext.Companion.ACCESS_TOKEN_ATTACHMENT_KEY
import io.nessus.identity.AuthorizationContext.Companion.AUTHORIZATION_CODE_ATTACHMENT_KEY
import io.nessus.identity.AuthorizationContext.Companion.EBSI32_AUTHORIZATION_REQUEST_DRAFT11_ATTACHMENT_KEY
import io.nessus.identity.AuthorizationContext.Companion.EBSI32_ISSUER_METADATA_ATTACHMENT_KEY
import io.nessus.identity.AuthorizationContext.Companion.EBSI32_PRESENTATION_SUBMISSION_ATTACHMENT_KEY
import io.nessus.identity.LoginContext
import io.nessus.identity.config.ConfigProvider.requireEbsiConfig
import io.nessus.identity.service.CredentialOfferRegistry.removeCredentialOfferRecord
import io.nessus.identity.types.AuthorizationMetadata
import io.nessus.identity.types.AuthorizationRequest
import io.nessus.identity.types.AuthorizationRequestDraft11
import io.nessus.identity.types.AuthorizationRequestV0
import io.nessus.identity.types.Constants.WELL_KNOWN_OPENID_CONFIGURATION
import io.nessus.identity.types.CredentialMatcherDraft11
import io.nessus.identity.types.CredentialOfferDraft11
import io.nessus.identity.types.TokenRequest
import io.nessus.identity.types.TokenResponse
import io.nessus.identity.types.authenticationId
import io.nessus.identity.types.publicKeyJwk
import io.nessus.identity.utils.HttpStatusException
import io.nessus.identity.utils.http
import io.nessus.identity.utils.signWithKey
import io.nessus.identity.utils.urlQueryToMap
import io.nessus.identity.utils.verifyJwtSignature
import io.nessus.identity.waltid.WaltIDServiceProvider.widWalletService
import kotlinx.serialization.json.*
import java.time.Instant
import java.util.*
import kotlin.uuid.Uuid

// NativeAuthorizationBackend ==========================================================================================

open class NativeAuthorizationService(override val endpointUri: String): AuthorizationService {

    val log = KotlinLogging.logger {}

    override fun getAuthorizationMetadata(ctx: LoginContext): AuthorizationMetadata {
        val targetUri = "$endpointUri/${ctx.targetId}"
        val jsonObj = Json.parseToJsonElement("""
            {
              "authorization_endpoint": "$targetUri/authorize",
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
              "issuer": "$targetUri",
              "jwks_uri": "$targetUri/jwks",
              "redirect_uris": [
                "$targetUri/direct_post"
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
              "token_endpoint": "$targetUri/token",
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
        """.trimIndent()).jsonObject
        return AuthorizationMetadata(jsonObj)
    }

    override fun getAuthorizationMetadataUrl(ctx: LoginContext): String {
        val metadataUrl = "$endpointUri/${ctx.targetId}/$WELL_KNOWN_OPENID_CONFIGURATION"
        return metadataUrl
    }

    override suspend fun createIDToken(
        ctx: LoginContext,
        idTokenRequest: AuthorizationRequest
    ): SignedJWT {

        val request = idTokenRequest.request
        val requestUri = idTokenRequest.requestUri
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
        val idTokenJwt = createIDTokenJwt(ctx, idTokenRequest, idTokenRequestJwt)
        return idTokenJwt
    }

    override fun createIDTokenAuthorizationRequest(
        redirectUri: String,
        idTokenRequestJwt: SignedJWT
    ): AuthorizationRequest {

        val claims = idTokenRequestJwt.jwtClaimsSet
        val queryParams = buildMap {
            listOf("client_id", "nonce", "scope", "redirect_uri", "response_mode", "response_type")
                .forEach { k -> put(k, claims.getClaim(k) as String) }
            put("request", idTokenRequestJwt.serialize())
        }

        val authRequest = AuthorizationRequestV0.fromHttpParameters(queryParams)
        log.info { "IDToken Request: ${authRequest.toRequestUrl(redirectUri)}" }
        queryParams.forEach { (k, v) -> log.info { "  $k=$v" } }

        return authRequest
    }

    override suspend fun createIDTokenJwt(
        ctx: LoginContext,
        authRequest: AuthorizationRequest,
        idTokenRequestJwt: SignedJWT
    ): SignedJWT {

        val reqParams = authRequest.toRequestParameters().mapValues{ (_, vs) -> vs.first() }.toMutableMap()
        for ((k, v) in idTokenRequestJwt.jwtClaimsSet.claims) {
            reqParams[k] = "$v"
        }

        // The Wallet answers the ID Token Request by providing the id_token in the redirect_uri as instructed by response_mode of direct_post.
        // The id_token must be signed with the DID document's authentication key.

        // Verify required query params
        for (key in listOf("client_id", "redirect_uri", "response_type")) {
            requireNotNull(reqParams[key]) { "No $key" }
        }

        val clientId = requireNotNull(reqParams["client_id"])
        val nonce = reqParams["nonce"]
        val state = reqParams["state"]

        val responseType = reqParams["response_type"]
        require(responseType == "id_token") { "Unexpected response_type: $responseType" }

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

        nonce?.also { jwtBuilder.claim("nonce", it) }
        state?.also { jwtBuilder.claim("state", it) }
        val idTokenClaims = jwtBuilder.build()

        val idTokenJwt = SignedJWT(idTokenHeader, idTokenClaims).signWithKey(ctx, kid)

        log.info { "IDToken: ${idTokenJwt.serialize()}" }
        idTokenJwt.verifyJwtSignature("IDToken", ctx.didInfo)

        return idTokenJwt
    }

    override suspend fun createIDTokenRequest(
        ctx: LoginContext,
        authRequest: AuthorizationRequest
    ): AuthorizationRequest {

        val authContext = ctx.getAuthContext()
        authRequest as AuthorizationRequestDraft11
        authContext.putAttachment(EBSI32_AUTHORIZATION_REQUEST_DRAFT11_ATTACHMENT_KEY, authRequest)

        val targetEndpointUri = "${endpointUri}/${ctx.targetId}"
        val redirectUri = requireNotNull(authRequest.redirectUri) { "No redirect_uri" }
        val idTokenRequestJwt = createIDTokenRequestJwt(ctx, targetEndpointUri, authRequest)
        val authRequestOut = createIDTokenAuthorizationRequest(redirectUri, idTokenRequestJwt)
        return authRequestOut
    }

    override suspend fun createIDTokenRequestJwt(
        ctx: LoginContext,
        targetEndpointUri: String,
        authReq: AuthorizationRequest
    ): SignedJWT {

        val requesterDid = requireEbsiConfig().requesterDid

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
        return idTokenJwt
    }

    override fun getIDTokenRedirectUrl(ctx: LoginContext, idTokenJwt: SignedJWT): String {

        // [TODO #233] Verify IDToken proof DID ownership
        // https://github.com/tdiesler/nessus-identity/issues/233
        // We should be able to use the Holder's public key to do that

        val authCode = "${Uuid.random()}"
        val authContext = ctx.getAuthContext()
        val authReq = authContext.assertAttachment(EBSI32_AUTHORIZATION_REQUEST_DRAFT11_ATTACHMENT_KEY)
        val idTokenRedirect = URLBuilder("${authReq.redirectUri}").apply {
            parameters.append("code", authCode)
            authReq.state?.also { state ->
                parameters.append("state", state)
            }
        }.buildString()
        authContext.putAttachment(AUTHORIZATION_CODE_ATTACHMENT_KEY, authCode)

        log.info { "IDToken Response $idTokenRedirect" }
        urlQueryToMap(idTokenRedirect).also {
            it.forEach { (k, v) -> log.info { "  $k=$v" } }
        }

        return idTokenRedirect
    }

    suspend fun createVPTokenDraft11(
        ctx: LoginContext,
        vpTokenRequest: AuthorizationRequestDraft11
    ): SignedJWT {

        log.info { "VPToken AuthorizationRequest: ${Json.encodeToString(vpTokenRequest)}" }

        val clientId = vpTokenRequest.clientId
        val nonce = vpTokenRequest.nonce
        val state = vpTokenRequest.state

        val vpdef = vpTokenRequest.presentationDefinition
            ?: throw IllegalStateException("No presentationDefinition in: $vpTokenRequest")

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
        val matchingCredentials = findCredentialsByPresentationDefinition(ctx, vpdef).toMap()
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

        val authContext = ctx.getAuthContext()
        authContext.putAttachment(EBSI32_PRESENTATION_SUBMISSION_ATTACHMENT_KEY, vpSubmission)

        return vpTokenJwt
    }

    /**
     * For every InputDescriptor iterate over all WalletCredentialsService and match all constraints.
     */
    suspend fun findCredentialsByPresentationDefinition(ctx: LoginContext, vpdef: PresentationDefinition): List<Pair<InputDescriptor, WalletCredential>> {
        val foundCredentials = mutableListOf<Pair<InputDescriptor, WalletCredential>>()
        val walletCredentials = widWalletService.listCredentials(ctx)
        val credMatcher = CredentialMatcherDraft11()
        for (wc in walletCredentials) {
            for (ind in vpdef.inputDescriptors) {
                if (credMatcher.matchCredential(wc, ind)) {
                    foundCredentials.add(Pair(ind, wc))
                    break
                }
            }
        }
        return foundCredentials
    }

    suspend fun sendVPTokenDraft11(
        ctx: LoginContext,
        vpTokenRequest: AuthorizationRequest,
        vpTokenJwt: SignedJWT
    ): String {

        val authContext = ctx.getAuthContext()
        val vpSubmission = authContext.assertAttachment(EBSI32_PRESENTATION_SUBMISSION_ATTACHMENT_KEY, true)

        val redirectUri = requireNotNull(vpTokenRequest.redirectUri) { "No redirectUri in: $vpTokenRequest" }
        val state = requireNotNull(vpTokenRequest.state) { "No state in: $vpTokenRequest" }

        log.info { "Send VPToken: $redirectUri" }
        val formData = mapOf(
            "vp_token" to "${vpTokenJwt.serialize()}",
            "presentation_submission" to Json.encodeToString(vpSubmission),
            "state" to state,
        )

        val res = http.post(redirectUri) {
            contentType(ContentType.Application.FormUrlEncoded)
            setBody(FormDataContent(Parameters.build {
                formData.forEach { (k, v) -> log.info { "  $k=$v"} }
                formData.forEach { (k, v) -> append(k, v) }
            }))
        }

        if (res.status != HttpStatusCode.Found)
            throw HttpStatusException(res.status, res.bodyAsText())

        val location = res.headers["location"]?.also {
            log.info { "VPToken Response: $it" }
        } ?: throw IllegalStateException("Cannot find 'location' in headers")

        val authCode = urlQueryToMap(location)["code"]?.also {
            authContext.putAttachment(AUTHORIZATION_CODE_ATTACHMENT_KEY, it)
        } ?: throw IllegalStateException("No authorization code")

        return authCode
    }

    override suspend fun getTokenResponse(ctx: LoginContext, tokenRequest: TokenRequest): TokenResponse {
        val tokenResponse = when (tokenRequest) {
            is TokenRequest.AuthorizationCode -> {
                getTokenResponseAuthCode(ctx, tokenRequest)
            }
            is TokenRequest.PreAuthorizedCode -> {
                getTokenResponsePreAuthorized(ctx, tokenRequest)
            }
            else -> error("Unsupported grant_type: ${tokenRequest.grantType}")
        }
        return tokenResponse
    }

    override suspend fun sendIDToken(
        ctx: LoginContext,
        idTokenRequest: AuthorizationRequest,
        idTokenJwt: SignedJWT
    ): String {

        val redirectUri = requireNotNull(idTokenRequest.redirectUri) { "No redirect_uri" }

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
        } ?: error("Cannot find 'location' in headers")

        val authCode = urlQueryToMap(location)["code"]?.also {
            val authContext = ctx.getAuthContext()
            authContext.putAttachment(AUTHORIZATION_CODE_ATTACHMENT_KEY, it)
        } ?: error("No authorization code")

        return authCode
    }

    override fun validateAccessToken(accessToken: SignedJWT) {

        val claims = accessToken.jwtClaimsSet
        val exp = claims.expirationTime?.toInstant()
        if (exp == null || exp.isBefore(Instant.now()))
            throw IllegalStateException("Token expired")

        // [TODO #235] Properly validate the AccessToken
        // https://github.com/tdiesler/nessus-identity/issues/235
    }

    // Private ---------------------------------------------------------------------------------------------------------

    private suspend fun buildTokenResponse(ctx: LoginContext): TokenResponse {

        val keyJwk = ctx.didInfo.publicKeyJwk()
        val kid = keyJwk["kid"]?.jsonPrimitive?.content as String

        val iat = Instant.now()
        val expiresIn: Long = 86400
        val exp = iat.plusSeconds(expiresIn)

        val nonce = "${Uuid.random()}"

        val authContext = ctx.getAuthContext()
        val issuerMetadata = authContext.assertAttachment(EBSI32_ISSUER_METADATA_ATTACHMENT_KEY)
        val tokenHeader = JWSHeader.Builder(JWSAlgorithm.ES256).type(JOSEObjectType.JWT).keyID(kid).build()

        val claimsBuilder = JWTClaimsSet.Builder().issuer(issuerMetadata.credentialIssuer).issueTime(Date.from(iat))
            .expirationTime(Date.from(exp)).claim("nonce", nonce)

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

    private suspend fun getTokenResponseAuthCode(ctx: LoginContext, tokenReq: TokenRequest): TokenResponse {

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

    private suspend fun getTokenResponsePreAuthorized(ctx: LoginContext, tokenReq: TokenRequest): TokenResponse {

        val clientId = tokenReq.clientId
        val preAuthTokenRequest = tokenReq as TokenRequest.PreAuthorizedCode
        val preAuthCode = preAuthTokenRequest.preAuthorizedCode
        val userPin = preAuthTokenRequest.userPin

        // Verify pre-authorized user PIN
        //
        val credOfferRecord = removeCredentialOfferRecord(preAuthCode)
            ?: error("No CredentialOffer registered")

        val expUserPin = credOfferRecord.userPin
        require(expUserPin == null || userPin == expUserPin) { "Invalid UserPin" }

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

