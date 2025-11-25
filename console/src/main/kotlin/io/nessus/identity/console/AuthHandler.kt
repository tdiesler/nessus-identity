package io.nessus.identity.console

import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import io.github.oshai.kotlinlogging.KotlinLogging
import io.ktor.client.request.*
import io.ktor.client.statement.*
import io.ktor.http.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import io.nessus.identity.config.ConfigProvider.requireEbsiConfig
import io.nessus.identity.extend.signWithKey
import io.nessus.identity.service.AuthorizationContext.Companion.EBSI32_AUTHORIZATION_REQUEST_ATTACHMENT_KEY
import io.nessus.identity.service.AuthorizationContext.Companion.EBSI32_AUTH_CODE_ATTACHMENT_KEY
import io.nessus.identity.service.HttpStatusException
import io.nessus.identity.service.LoginContext
import io.nessus.identity.service.LoginContext.Companion.AUTH_CONTEXT_ATTACHMENT_KEY
import io.nessus.identity.service.WalletAuthorizationService
import io.nessus.identity.service.WalletService
import io.nessus.identity.service.http
import io.nessus.identity.service.urlQueryToMap
import io.nessus.identity.types.AuthorizationRequestDraft11
import io.nessus.identity.waltid.publicKeyJwk
import kotlinx.serialization.json.*
import java.time.Instant
import java.util.*
import kotlin.uuid.Uuid

abstract class AuthHandler {

    val log = KotlinLogging.logger {}

    val jsonPretty = Json { prettyPrint = true }

    val walletSvc: WalletService = WalletService.createKeycloak()
    val walletAuthSvc = WalletAuthorizationService(walletSvc)

    abstract val endpointUri: String

    fun buildAuthCodeRedirectUri(ctx: LoginContext, authCode: String): String {

        val authContext = ctx.assertAttachment(AUTH_CONTEXT_ATTACHMENT_KEY)
        val authReq = authContext.assertAttachment(EBSI32_AUTHORIZATION_REQUEST_ATTACHMENT_KEY)
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

    suspend fun buildIDTokenRequest(ctx: LoginContext, authReq: AuthorizationRequestDraft11): SignedJWT {

        val requesterDid = requireEbsiConfig().requesterDid
        val targetEndpointUri = "$endpointUri/${ctx.targetId}"

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

    fun buildIDTokenRedirectUrl(redirectUri: String, idTokenReqJwt: SignedJWT): String {

        val claims = idTokenReqJwt.jwtClaimsSet
        val idTokenRedirectUrl = URLBuilder(redirectUri).apply {
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

    suspend fun handleIDTokenRequest(call: RoutingCall, ctx: LoginContext) {

        val authContext = ctx.assertAttachment(AUTH_CONTEXT_ATTACHMENT_KEY)

        val reqParams = urlQueryToMap(call.request.uri).toMutableMap()
        val redirectUri = reqParams["redirect_uri"] as String
        val requestUri = reqParams["request_uri"]

        // Replace IDToken request params with the response from request_uri
        if (requestUri != null) {
            log.info { "IDToken params from: $requestUri" }
            val res = http.get(requestUri)
            if (res.status != HttpStatusCode.OK)
                throw HttpStatusException(res.status, res.bodyAsText())
            val uriRes = res.bodyAsText()
            log.info { "UriResponse: $uriRes" }
            val resJwt = SignedJWT.parse(uriRes)
            log.info { "UriResponse Header: ${resJwt.header}" }
            log.info { "UriResponse Claims: ${resJwt.jwtClaimsSet}" }
            for ((k, v) in resJwt.jwtClaimsSet.claims) {
                reqParams[k] = "$v"
            }
        } else {
            reqParams["response_type"] = "id_token"
        }

        val idTokenJwt = walletAuthSvc.createIDToken(ctx, reqParams)
        walletAuthSvc.sendIDToken(authContext, redirectUri, idTokenJwt)

        call.respondText(
            status = HttpStatusCode.Accepted,
            contentType = ContentType.Text.Plain,
            text = "Accepted"
        )
    }

    suspend fun handleJwksRequest(call: RoutingCall, ctx: LoginContext) {

        val keyJwk = ctx.didInfo.publicKeyJwk()
        val keys = mapOf("keys" to listOf(keyJwk))
        val payload = Json.encodeToString(keys)

        log.info { "Jwks $payload" }

        call.respondText(
            status = HttpStatusCode.OK,
            contentType = ContentType.Application.Json,
            text = payload
        )
    }

    fun validateIDToken(ctx: LoginContext, idTokenJwt: SignedJWT): String {

        log.info { "IDToken Header: ${idTokenJwt.header}" }
        log.info { "IDToken Claims: ${idTokenJwt.jwtClaimsSet}" }

        // [TODO #233] Verify IDToken proof DID ownership
        // https://github.com/tdiesler/nessus-identity/issues/233
        // We should be able to use the Holder's public key to do that

        val authCode = "${Uuid.random()}"
        val authContext = ctx.assertAttachment(AUTH_CONTEXT_ATTACHMENT_KEY)
        authContext.putAttachment(EBSI32_AUTH_CODE_ATTACHMENT_KEY, authCode)

        val authReq = authContext.assertAttachment(EBSI32_AUTHORIZATION_REQUEST_ATTACHMENT_KEY)
        val idTokenRedirect = URLBuilder("${authReq.redirectUri}").apply {
            parameters.append("code", authCode)
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

    // Private -------------------------------------------------------------------------------------------------------------------------------------------------

}
