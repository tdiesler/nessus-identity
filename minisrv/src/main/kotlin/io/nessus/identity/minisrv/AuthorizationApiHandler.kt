package io.nessus.identity.minisrv

import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.util.JSONObjectUtils
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import id.walt.crypto.utils.JsonUtils.toJsonElement
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
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import io.ktor.util.*
import io.nessus.identity.AuthorizationContext.Companion.AUTHORIZATION_CODE_ATTACHMENT_KEY
import io.nessus.identity.AuthorizationContext.Companion.AUTHORIZATION_REQUEST_ATTACHMENT_KEY
import io.nessus.identity.AuthorizationContext.Companion.EBSI32_AUTHORIZATION_REQUEST_DRAFT11_ATTACHMENT_KEY
import io.nessus.identity.AuthorizationContext.Companion.EBSI32_PRESENTATION_SUBMISSION_ATTACHMENT_KEY
import io.nessus.identity.AuthorizationContext.Companion.EBSI32_REQUEST_URI_OBJECT_ATTACHMENT_KEY
import io.nessus.identity.LoginContext
import io.nessus.identity.service.AuthorizationService
import io.nessus.identity.types.AuthorizationRequestDraft11
import io.nessus.identity.types.AuthorizationRequestV0
import io.nessus.identity.types.CredentialMatcherDraft11
import io.nessus.identity.types.TokenRequest
import io.nessus.identity.types.UserRole
import io.nessus.identity.types.W3CCredentialV11Jwt
import io.nessus.identity.types.W3CCredentialValidator
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

    suspend fun handleVPTokenRequest(call: RoutingCall, ctx: LoginContext) {

        val reqParams = urlQueryToMap(call.request.uri)

        // Final Qualification Credential use case ...
        //
        //  - EBSI offers the CTWalletQualificationCredential
        //  - Holder sends an AuthorizationRequest, EBSI responds with an 302 Redirect (WalletBackend.sendAuthorizationRequest)
        //  - Cloudflare may deny that redirect URL because of a very large 'request' query parameter
        //  - The content of that request parameter is a serialized AuthorizationRequest object
        //  - We rewrite the redirect URL using a request_uri parameter, which resolves to that AuthorizationRequest
        //  - Here, we restore that AuthorizationRequest and use it's PresentationDefinition to build the VPToken

        // [TODO #229] Access to request_uri object not thread safe
        // https://github.com/tdiesler/nessus-identity/issues/229

        val authContext = ctx.getAuthContext()

        val requestUri = reqParams["request_uri"]
        if (requestUri != null) {

            require(requestUri.startsWith(endpointUri)) { "Unexpected request_uri: $requestUri" }
            requireNotNull(urlQueryToMap(requestUri)["request_object"]) { "No request_object in: $requestUri" }
            val authRequest = authContext.assertAttachment(EBSI32_REQUEST_URI_OBJECT_ATTACHMENT_KEY)

            val vpTokenJwt = createVPTokenDraft11(ctx, authRequest)
            sendVPTokenDraft11(ctx, vpTokenJwt)

            call.respondText(
                status = HttpStatusCode.Accepted,
                contentType = ContentType.Text.Plain,
                text = "Accepted"
            )

        } else {

            val authRequest = AuthorizationRequestV0.fromHttpParameters(reqParams)
            authContext.putAttachment(AUTHORIZATION_REQUEST_ATTACHMENT_KEY, authRequest)
            return call.respondRedirect("/wallet/${ctx.targetId}/flow/vp-token-consent?state=ask")
        }
    }

    // Private -------------------------------------------------------------------------------------------------------------------------------------------------

    suspend fun createVPTokenDraft11(
        ctx: LoginContext,
        authReq: AuthorizationRequestDraft11
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

    suspend fun sendVPTokenDraft11(
        ctx: LoginContext,
        vpTokenJwt: SignedJWT
    ): String {

        val authContext = ctx.getAuthContext()
        val reqObject = authContext.assertAttachment(EBSI32_REQUEST_URI_OBJECT_ATTACHMENT_KEY)
        val vpSubmission = authContext.assertAttachment(EBSI32_PRESENTATION_SUBMISSION_ATTACHMENT_KEY, true)

        val redirectUri = requireNotNull(reqObject.redirectUri) { "No redirectUri in: $reqObject" }
        val state = requireNotNull(reqObject.state) { "No state in: $reqObject" }

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