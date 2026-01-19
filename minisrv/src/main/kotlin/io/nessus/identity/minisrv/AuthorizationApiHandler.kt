package io.nessus.identity.minisrv

import com.nimbusds.jwt.SignedJWT
import id.walt.crypto.utils.JsonUtils.toJsonElement
import io.github.oshai.kotlinlogging.KotlinLogging
import io.ktor.http.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import io.ktor.util.*
import io.nessus.identity.AuthorizationContext.Companion.EBSI32_AUTHORIZATION_REQUEST_DRAFT11_ATTACHMENT_KEY
import io.nessus.identity.LoginContext
import io.nessus.identity.service.AuthorizationService
import io.nessus.identity.types.TokenRequest
import io.nessus.identity.types.UserRole
import io.nessus.identity.types.W3CCredentialV11Jwt
import io.nessus.identity.types.W3CCredentialValidator
import io.nessus.identity.types.publicKeyJwk
import io.nessus.identity.utils.urlQueryToMap
import kotlinx.serialization.json.*
import java.util.*
import kotlin.uuid.Uuid

open class AuthorizationApiHandler(
    val userRole: UserRole,
    val authorizationSvc: AuthorizationService,
) {
    val log = KotlinLogging.logger {}

    val endpointUri = authorizationSvc.endpointUri

    suspend fun handleAuthorizationMetadataRequest(call: RoutingCall, ctx: LoginContext) {
        val payload = Json.encodeToString(authorizationSvc.getAuthorizationMetadata(ctx))
        call.respondText(
            status = HttpStatusCode.OK,
            contentType = ContentType.Application.Json,
            text = payload
        )
    }

    suspend fun handleDirectPost(call: RoutingCall, ctx: LoginContext) {

        val postParams = call.receiveParameters().toMap()
        log.info { "$userRole DirectPost: ${call.request.uri}" }
        postParams.forEach { (k, lst) -> lst.forEach { v -> log.info { "  $k=$v" } } }

        if (postParams["id_token"] != null) {
            val idToken = postParams["id_token"]?.first()
            val idTokenJwt = SignedJWT.parse(idToken)
            val redirectUrl = authorizationSvc.getIDTokenRedirectUrl(ctx, idTokenJwt)
            return call.respondRedirect(redirectUrl)
        }

        if (postParams["vp_token"] != null) {
            val redirectUrl = handleVPTokenResponse(ctx, postParams)
            return call.respondRedirect(redirectUrl)
        }

        call.respondText(
            status = HttpStatusCode.InternalServerError,
            contentType = ContentType.Text.Plain,
            text = "Not Implemented"
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

    suspend fun handleTokenRequest(call: RoutingCall, ctx: LoginContext) {

        val postParams = call.receiveParameters().toMap().toMutableMap()
        log.info { "Token Request: ${call.request.uri}" }
        postParams.forEach { (k, lst) -> lst.forEach { v -> log.info { "  $k=$v" } } }

        val tokenRequest = TokenRequest.fromHttpParameters(postParams)
        val tokenResponse = authorizationSvc.getTokenResponse(ctx, tokenRequest)

        call.respondText(
            status = HttpStatusCode.OK,
            contentType = ContentType.Application.Json,
            text = Json.encodeToString(tokenResponse)
        )
    }

    // Private -------------------------------------------------------------------------------------------------------------------------------------------------


    private fun handleVPTokenResponse(ctx: LoginContext, postParams: Map<String, List<String>>): String {

        val vpToken = postParams["vp_token"]?.firstOrNull() ?: error("No vp_token")

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

        val authContext = ctx.getAuthContext()
        val authReq = authContext.assertAttachment(EBSI32_AUTHORIZATION_REQUEST_DRAFT11_ATTACHMENT_KEY)
        val urlBuilder = URLBuilder("${authReq.redirectUri}")

        val vcArray = vpClaims.getClaim("vp").toJsonElement().jsonObject["verifiableCredential"]?.jsonArray

        // Validate Credentials
        //
        var validationError: Throwable? = null
        log.info { "VPToken VerifiableCredentials" }
        vcArray?.map { it.jsonPrimitive.content }?.forEach { vcEncoded ->
            val jwt = SignedJWT.parse(vcEncoded)
            log.info { "VC Encoded: $vcEncoded" }
            log.info { "   Header: ${jwt.header}" }
            log.info { "   Claims: ${jwt.jwtClaimsSet}" }
            runCatching {
                val vpcJwt = W3CCredentialV11Jwt.fromEncoded(vcEncoded)
                W3CCredentialValidator.validateVerifiableCredential(vpcJwt)
            }.onFailure {
                validationError = it
                urlBuilder.apply {
                    parameters.append("error", "invalid_request")
                    parameters.append("error_description", "${validationError.message}")
                }
            }
        }

        if (validationError == null) {
            urlBuilder.parameters.append("code", "${Uuid.random()}")
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


}