package io.nessus.identity.service

import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import io.github.oshai.kotlinlogging.KotlinLogging
import io.ktor.client.request.*
import io.ktor.client.request.forms.*
import io.ktor.client.statement.*
import io.ktor.http.*
import io.nessus.identity.config.ConfigProvider.requireEbsiConfig
import io.nessus.identity.extend.signWithKey
import io.nessus.identity.extend.verifyJwtSignature
import io.nessus.identity.service.AuthorizationContext.Companion.AUTHORIZATION_CODE_ATTACHMENT_KEY
import io.nessus.identity.service.AuthorizationContext.Companion.EBSI32_AUTHORIZATION_REQUEST_DRAFT11_ATTACHMENT_KEY
import io.nessus.identity.types.AuthorizationMetadata
import io.nessus.identity.types.AuthorizationRequest
import io.nessus.identity.waltid.authenticationId
import io.nessus.identity.waltid.publicKeyJwk
import kotlinx.serialization.json.*
import java.time.Instant
import java.util.*
import kotlin.uuid.Uuid

// NativeAuthorizationService ================================================================================================

class NativeAuthorizationService(): AuthorizationService {

    val log = KotlinLogging.logger {}

    override fun buildAuthorizationMetadata(targetUri: String): AuthorizationMetadata {
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

    override fun buildAuthCodeRedirectUri(ctx: LoginContext, authCode: String): String {

        val authContext = ctx.getAuthContext()
        val authReq = authContext.assertAttachment(EBSI32_AUTHORIZATION_REQUEST_DRAFT11_ATTACHMENT_KEY)
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

    override suspend fun buildIDTokenRequestJwt(
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
        log.info { "IDToken Request Header: ${idTokenJwt.header}" }
        log.info { "IDToken Request Claims: ${idTokenJwt.jwtClaimsSet}" }

        return idTokenJwt
    }

    override fun buildIDTokenRequestRedirectUrl(authRequest: AuthorizationRequest, idTokenRequestJwt: SignedJWT): String {

        val claims = idTokenRequestJwt.jwtClaimsSet
        val idTokenRedirectUrl = URLBuilder(authRequest.redirectUri!!).apply {
            for (k in listOf("client_id", "nonce", "scope", "redirect_uri", "response_mode", "response_type")) {
                val v = claims.getClaim(k) as String
                parameters.append(k, v)
            }
            parameters.append("request", "${idTokenRequestJwt.serialize()}")
        }.buildString()

        log.info { "IDToken Redirect $idTokenRedirectUrl" }
        urlQueryToMap(idTokenRedirectUrl).also {
            it.forEach { (k, v) -> log.info { "  $k=$v" } }
        }

        return idTokenRedirectUrl
    }

    override suspend fun createIDToken(
        ctx: LoginContext,
        reqParams: Map<String, String>
    ): SignedJWT {

        // Verify required query params
        for (key in listOf("client_id", "redirect_uri", "response_type")) {
            requireNotNull(reqParams[key]) { "Cannot find $key" }
        }

        // The Wallet answers the ID Token Request by providing the id_token in the redirect_uri as instructed by response_mode of direct_post.
        // The id_token must be signed with the DID document's authentication key.

        val clientId = reqParams["client_id"] as String

        val responseType = reqParams["response_type"] as String
        require(responseType == "id_token") { "Unexpected response_type: $responseType" }

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

    override suspend fun sendIDToken(
        ctx: LoginContext,
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
        } ?: error("Cannot find 'location' in headers")

        val authCode = urlQueryToMap(location)["code"]?.also {
            val authContext = ctx.getAuthContext()
            authContext.putAttachment(AUTHORIZATION_CODE_ATTACHMENT_KEY, it)
        } ?: error("No authorization code")

        return authCode
    }

    // Private -------------------------------------------------------------------------------------------------------------------------------------------------
}

