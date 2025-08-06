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
import id.walt.oid4vc.requests.AuthorizationRequest
import id.walt.oid4vc.requests.TokenRequest
import id.walt.oid4vc.responses.TokenResponse
import io.github.oshai.kotlinlogging.KotlinLogging
import io.ktor.http.URLBuilder
import io.nessus.identity.config.ConfigProvider.authEndpointUri
import io.nessus.identity.extend.getCredentialTypes
import io.nessus.identity.extend.signWithKey
import io.nessus.identity.extend.verifyJwtSignature
import io.nessus.identity.service.AttachmentKeys.ACCESS_TOKEN_ATTACHMENT_KEY
import io.nessus.identity.service.AttachmentKeys.AUTH_CODE_ATTACHMENT_KEY
import io.nessus.identity.service.AttachmentKeys.AUTH_REQUEST_ATTACHMENT_KEY
import io.nessus.identity.service.AttachmentKeys.ISSUER_METADATA_ATTACHMENT_KEY
import io.nessus.identity.service.CredentialOfferRegistry.isEBSIPreAuthorizedType
import io.nessus.identity.service.CredentialOfferRegistry.removeCredentialOfferRecord
import io.nessus.identity.service.IssuerService.ebsiDefaultHolderId
import io.nessus.identity.types.PresentationDefinitionBuilder
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

// AuthService =========================================================================================================

object AuthService {

    val log = KotlinLogging.logger {}

    fun getAuthMetadataUrl(ctx: LoginContext): String {
        val metadataUrl = OpenID4VCI.getOpenIdProviderMetadataUrl("$authEndpointUri/${ctx.targetId}")
        return metadataUrl
    }

    fun getAuthMetadata(ctx: LoginContext): JsonObject {
        val metadata = buildAuthEndpointMetadata(ctx)
        return metadata
    }

    fun buildAuthCodeRedirectUri(ctx: OIDCContext, authCode: String): String {

        val authReq = ctx.authRequest
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

    suspend fun buildIDTokenRequest(ctx: OIDCContext, authReq: AuthorizationRequest): SignedJWT {

        val issuerMetadata = ctx.issuerMetadata
        val authorizationServer = ctx.authorizationServer

        val keyJwk = ctx.didInfo.publicKeyJwk()
        val kid = keyJwk["kid"]?.jsonPrimitive?.content as String

        val iat = Instant.now()
        val exp = iat.plusSeconds(300) // 5 mins expiry

        val idTokenHeader = JWSHeader.Builder(JWSAlgorithm.ES256).type(JOSEObjectType.JWT).keyID(kid).build()

        @OptIn(ExperimentalUuidApi::class) val idTokenClaims =
            JWTClaimsSet.Builder().issuer(issuerMetadata.credentialIssuer).audience(authReq.clientId)
                .issueTime(Date.from(iat)).expirationTime(Date.from(exp)).claim("response_type", "id_token")
                .claim("response_mode", "direct_post").claim("client_id", issuerMetadata.credentialIssuer)
                .claim("redirect_uri", "$authorizationServer/direct_post").claim("scope", "openid")
                .claim("nonce", "${Uuid.random()}").build()

        val idTokenJwt = SignedJWT(idTokenHeader, idTokenClaims).signWithKey(ctx, kid)
        log.info { "IDToken Request Header: ${idTokenJwt.header}" }
        log.info { "IDToken Request Claims: ${idTokenJwt.jwtClaimsSet}" }

        return idTokenJwt
    }

    fun buildIDTokenRedirectUrl(ctx: OIDCContext, idTokenReqJwt: SignedJWT): String {

        val authReq = ctx.authRequest
        val claims = idTokenReqJwt.jwtClaimsSet
        val idTokenRedirectUrl = URLBuilder("${authReq.redirectUri}").apply {
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

    @OptIn(ExperimentalUuidApi::class)
    suspend fun buildVPTokenRequest(ctx: OIDCContext, authReq: AuthorizationRequest): SignedJWT {

        val issuerMetadata = ctx.issuerMetadata
        val authorizationServer = ctx.authorizationServer

        val keyJwk = ctx.didInfo.publicKeyJwk()
        val kid = keyJwk["kid"]?.jsonPrimitive?.content as String

        val iat = Instant.now()
        val exp = iat.plusSeconds(300) // 5 mins expiry
        val scopes = authReq.scope.joinToString(" ")

        val vpTokenHeader = JWSHeader.Builder(JWSAlgorithm.ES256).type(JOSEObjectType.JWT).keyID(kid).build()

        val presentationDefinition = authReq.presentationDefinition ?: run {

            if (authReq.scope != setOf(
                    "openid",
                    "ver_test:vp_token"
                )
            ) throw IllegalStateException("No PresentationDefinition")

            // EBSI wants exactly three InputDescriptor(s)
            // Authorization endpoint's response doesn't contain a valid JWT payload in the VP Token request
            // Validation error. Path: 'presentation_definition.input_descriptors'. Reason: Array must contain exactly 3 element(s)
            PresentationDefinitionBuilder().withInputDescriptorForType("VerifiableAttestation")
                .withInputDescriptorForType("VerifiableAttestation").withInputDescriptorForType("VerifiableAttestation")
                .build()
        }

        val presentationDefinitionJson = Json.encodeToString(presentationDefinition)
        log.info { "PresentationDefinition: $presentationDefinitionJson" }

        @OptIn(ExperimentalUuidApi::class) val vpTokenClaims =
            JWTClaimsSet.Builder().issuer(issuerMetadata.credentialIssuer).audience(authReq.clientId)
                .issueTime(Date.from(iat)).expirationTime(Date.from(exp)).claim("response_type", "vp_token")
                .claim("response_mode", "direct_post").claim("client_id", issuerMetadata.credentialIssuer)
                .claim("redirect_uri", "$authorizationServer/direct_post").claim("scope", scopes)
                .claim("nonce", "${Uuid.random()}")
                .claim("presentation_definition", JSONObjectUtils.parse(presentationDefinitionJson)).build()

        val vpTokenReqJwt = SignedJWT(vpTokenHeader, vpTokenClaims).signWithKey(ctx, kid)
        log.info { "VPTokenRequest Header: ${vpTokenReqJwt.header}" }
        log.info { "VPTokenRequest Claims: ${vpTokenReqJwt.jwtClaimsSet}" }

        return vpTokenReqJwt
    }

    fun buildVPTokenRedirectUrl(ctx: OIDCContext, vpTokenReqJwt: SignedJWT): String {

        val authorizationServer = ctx.authorizationServer

        val authReq = ctx.assertAttachment(AUTH_REQUEST_ATTACHMENT_KEY)
        val scopes = authReq.scope.joinToString(" ")

        val vpTokenRedirectUrl = URLBuilder("${authReq.redirectUri}").apply {
            parameters.append("client_id", authReq.clientId) // Holder Did
            parameters.append("response_type", "vp_token")
            parameters.append("response_mode", "direct_post")
            parameters.append("scope", scopes)
            parameters.append("redirect_uri", "$authorizationServer/direct_post")
            // [TODO #226] Check with the spec whether the VPToken request payload is an AuthorizationRequest
            // [TODO #227] May need to use request_uri for VPToken Request redirect url
            parameters.append("request", "${vpTokenReqJwt.serialize()}")
        }.buildString()

        log.info { "VPToken Redirect $vpTokenRedirectUrl" }
        urlQueryToMap(vpTokenRedirectUrl).also {
            it.forEach { (k, v) -> log.info { "  $k=$v" } }
        }

        return vpTokenRedirectUrl
    }

    @OptIn(ExperimentalUuidApi::class)
    suspend fun handleTokenRequestAuthCode(ctx: OIDCContext, tokenReq: TokenRequest): TokenResponse {

        val tokReq = tokenReq as TokenRequest.AuthorizationCode
        val grantType = tokReq.grantType
        val codeVerifier = tokReq.codeVerifier
        val redirectUri = tokReq.redirectUri
        val code = tokReq.code

        // Verify token request
        //
        if (tokReq.clientId != ctx.authRequest.clientId) throw IllegalArgumentException("Invalid client_id: ${tokReq.clientId}")

        // [TODO #230] Verify token request code challenge

        val tokenRes = buildTokenResponse(ctx)
        return tokenRes
    }

    suspend fun handleTokenRequestPreAuthorized(ctx: OIDCContext, tokenReq: TokenRequest): TokenResponse {

        if (!ctx.hasAttachment(ISSUER_METADATA_ATTACHMENT_KEY)) ctx.putAttachment(
            ISSUER_METADATA_ATTACHMENT_KEY,
            IssuerService.getIssuerMetadata(ctx)
        )

        var subId = tokenReq.clientId
        val preAuthTokenRequest = tokenReq as TokenRequest.PreAuthorizedCode
        val preAuthCode = preAuthTokenRequest.preAuthorizedCode
        val userPin = preAuthTokenRequest.userPIN

        // In the EBSI Issuer Conformance Test, the preAuthCode is a known Credential type
        // and the clientId associated with the TokenRequest is undefined
        if (isEBSIPreAuthorizedType(preAuthCode)) {
            if (subId == null)
                subId = ebsiDefaultHolderId
        }

        // Verify pre-authorized user PIN
        //
        val credOfferRecord = removeCredentialOfferRecord(preAuthCode)
            ?: throw IllegalStateException("No CredentialOffer registered")
        val expUserPin = credOfferRecord.userPin
            ?: throw IllegalStateException("No UserPin")

        if (userPin != expUserPin)
            throw IllegalStateException("Invalid UserPin")

        val credOffer = credOfferRecord.credOffer
        val types = credOffer?.getCredentialTypes()
        val authRequest = AuthorizationRequest(
            clientId = subId ?: throw IllegalStateException("No subId"), authorizationDetails = listOf(
                AuthorizationDetails(
                    format = CredentialFormat.jwt_vc, types = types
                )
            )
        )

        ctx.putAttachment(AUTH_REQUEST_ATTACHMENT_KEY, authRequest)

        val tokenResponse = buildTokenResponse(ctx)
        return tokenResponse
    }

    /**
     * Handle AuthorizationRequest from remote Holder
     */
    fun validateAuthorizationRequest(ctx: OIDCContext, authReq: AuthorizationRequest) {

        // Attach issuer metadata (on demand)
        //
        if (!ctx.hasAttachment(ISSUER_METADATA_ATTACHMENT_KEY)) {
            val issuerMetadata = IssuerService.getIssuerMetadata(ctx)
            ctx.putAttachment(ISSUER_METADATA_ATTACHMENT_KEY, issuerMetadata)
        }

        // Validate the AuthorizationRequest
        //
        // [TODO #232] Check VC types in authorization_details

        ctx.putAttachment(AUTH_REQUEST_ATTACHMENT_KEY, authReq)
    }

    @OptIn(ExperimentalUuidApi::class)
    fun validateIDToken(ctx: OIDCContext, idTokenJwt: SignedJWT): String {

        log.info { "IDToken Header: ${idTokenJwt.header}" }
        log.info { "IDToken Claims: ${idTokenJwt.jwtClaimsSet}" }

        // [TODO #233] Verify IDToken proof DID ownership
        // We should be able to use the Holder's public key to do that

        val authCode = "${Uuid.random()}"
        ctx.putAttachment(AUTH_CODE_ATTACHMENT_KEY, authCode)

        val authReq = ctx.authRequest
        val idTokenRedirect = URLBuilder("${authReq.redirectUri}").apply {
            parameters.append("code", ctx.authCode)
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

    // Private ---------------------------------------------------------------------------------------------------------

    @OptIn(ExperimentalUuidApi::class)
    private suspend fun buildTokenResponse(ctx: OIDCContext): TokenResponse {
        val keyJwk = ctx.didInfo.publicKeyJwk()
        val kid = keyJwk["kid"]?.jsonPrimitive?.content as String

        val iat = Instant.now()
        val expiresIn: Long = 86400
        val exp = iat.plusSeconds(expiresIn)

        val nonce = "${Uuid.random()}"

        val tokenHeader = JWSHeader.Builder(JWSAlgorithm.ES256).type(JOSEObjectType.JWT).keyID(kid).build()

        val claimsBuilder = JWTClaimsSet.Builder().issuer(ctx.issuerMetadata.credentialIssuer).issueTime(Date.from(iat))
            .expirationTime(Date.from(exp)).claim("nonce", nonce)

        ctx.maybeAuthRequest?.clientId?.also {
            claimsBuilder.subject(it)
        }
        ctx.maybeAuthRequest?.authorizationDetails?.also {
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

        val tokenResponse = TokenResponse.fromJSONString(tokenRespJson).also {
            ctx.putAttachment(ACCESS_TOKEN_ATTACHMENT_KEY, accessTokenJwt)
        }
        log.info { "Token Response: ${Json.encodeToString(tokenResponse)}" }
        return tokenResponse
    }

    private fun buildAuthEndpointMetadata(ctx: LoginContext): JsonObject {
        val baseUrl = "$authEndpointUri/${ctx.targetId}"
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
}

