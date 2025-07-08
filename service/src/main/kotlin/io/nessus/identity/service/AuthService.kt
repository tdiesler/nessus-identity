package io.nessus.identity.service

import com.nimbusds.jwt.SignedJWT
import id.walt.oid4vc.data.GrantDetails
import id.walt.oid4vc.requests.TokenRequest
import id.walt.oid4vc.responses.TokenResponse
import io.github.oshai.kotlinlogging.KotlinLogging
import io.ktor.client.request.*
import io.ktor.client.request.forms.*
import io.ktor.client.statement.*
import io.ktor.http.*
import io.nessus.identity.api.AuthServiceApi

// WalletService =======================================================================================================

object AuthService : AuthServiceApi {

    val log = KotlinLogging.logger {}

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

}