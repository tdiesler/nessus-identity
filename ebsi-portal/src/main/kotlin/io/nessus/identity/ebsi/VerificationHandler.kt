package io.nessus.identity.ebsi

import com.nimbusds.jwt.SignedJWT
import id.walt.crypto.utils.JsonUtils.toJsonElement
import io.github.oshai.kotlinlogging.KotlinLogging
import io.ktor.http.URLBuilder
import io.nessus.identity.service.AttachmentKeys.AUTH_CODE_ATTACHMENT_KEY
import io.nessus.identity.service.OIDContext
import io.nessus.identity.service.VerifierService
import io.nessus.identity.service.urlQueryToMap
import io.nessus.identity.types.W3CCredentialJwt
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import java.util.Date
import kotlin.uuid.ExperimentalUuidApi
import kotlin.uuid.Uuid

object VerificationHandler {

    val log = KotlinLogging.logger {}

    @OptIn(ExperimentalUuidApi::class)
    fun handleVPTokenResponse(ctx: OIDContext, postParams: Map<String, List<String>>): String {

        val vpToken = postParams["vp_token"]?.firstOrNull() ?: throw IllegalStateException("No vp_token")

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

        val authReq = ctx.authRequest
        val urlBuilder = URLBuilder("${authReq.redirectUri}")

        val vcArray = vpClaims.getClaim("vp").toJsonElement().jsonObject["verifiableCredential"]?.jsonArray

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
                val w3Cred = W3CCredentialJwt.fromEncodedJwt(vcEncoded).vc
                VerifierService.validateVerifiableCredential(w3Cred)
            }.onFailure {
                validationError = it
                urlBuilder.apply {
                    parameters.append("error", "invalid_request")
                    parameters.append("error_description", "${validationError.message}")
                }
            }
        }

        if (validationError == null) {
            ctx.putAttachment(AUTH_CODE_ATTACHMENT_KEY, "${Uuid.random()}")
            urlBuilder.parameters.append("code", ctx.authCode)
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