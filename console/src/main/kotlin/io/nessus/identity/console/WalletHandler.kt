package io.nessus.identity.console

import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.util.JSONObjectUtils
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import id.walt.oid4vc.data.dif.DescriptorMapping
import id.walt.oid4vc.data.dif.InputDescriptor
import id.walt.oid4vc.data.dif.PresentationDefinition
import id.walt.oid4vc.data.dif.PresentationSubmission
import id.walt.w3c.utils.VCFormat
import id.walt.webwallet.db.models.WalletCredential
import io.ktor.client.request.*
import io.ktor.client.request.forms.*
import io.ktor.client.statement.*
import io.ktor.http.*
import io.ktor.server.freemarker.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import io.nessus.identity.config.ConfigProvider.requireEbsiConfig
import io.nessus.identity.config.ConfigProvider.requireWalletConfig
import io.nessus.identity.config.Features
import io.nessus.identity.config.Features.CREDENTIAL_OFFER_AUTO_FETCH
import io.nessus.identity.config.Features.CREDENTIAL_OFFER_STORE
import io.nessus.identity.config.User
import io.nessus.identity.extend.signWithKey
import io.nessus.identity.extend.verifyJwtSignature
import io.nessus.identity.service.AuthorizationContext.Companion.AUTHORIZATION_CODE_ATTACHMENT_KEY
import io.nessus.identity.service.AuthorizationContext.Companion.EBSI32_PRESENTATION_SUBMISSION_ATTACHMENT_KEY
import io.nessus.identity.service.AuthorizationContext.Companion.EBSI32_REQUEST_URI_OBJECT_ATTACHMENT_KEY
import io.nessus.identity.service.AuthorizationContext.Companion.USER_PIN_ATTACHMENT_KEY
import io.nessus.identity.service.CredentialMatcherDraft11
import io.nessus.identity.service.HttpStatusException
import io.nessus.identity.service.IssuerService.Companion.KNOWN_ISSUER_EBSI_V3
import io.nessus.identity.service.LoginContext
import io.nessus.identity.service.LoginContext.Companion.AUTH_REQUEST_ATTACHMENT_KEY
import io.nessus.identity.service.WalletService
import io.nessus.identity.service.getAuthCodeFromRedirectUrl
import io.nessus.identity.service.http
import io.nessus.identity.service.urlEncode
import io.nessus.identity.service.urlQueryToMap
import io.nessus.identity.types.AuthorizationRequestDraft11
import io.nessus.identity.types.AuthorizationRequestV0
import io.nessus.identity.types.CredentialOffer
import io.nessus.identity.types.UserRole
import io.nessus.identity.types.W3CCredentialJwt
import io.nessus.identity.types.W3CCredentialSdV11Jwt
import io.nessus.identity.types.W3CCredentialV11Jwt
import io.nessus.identity.waltid.LoginParams
import io.nessus.identity.waltid.LoginType
import io.nessus.identity.waltid.WaltIDServiceProvider.widWalletService
import io.nessus.identity.waltid.authenticationId
import kotlinx.serialization.json.*
import java.time.Instant
import java.util.*
import kotlin.uuid.Uuid

class WalletHandler(val walletSvc: WalletService) : AuthHandler(walletSvc.authorizationSvc) {

    override val endpointUri = walletSvc.endpointUri

    fun walletModel(call: RoutingCall, ctx: LoginContext? = null): BaseModel {
        val model =
            ctx?.let { BaseModel().withLoginContext(ctx) } ?: BaseModel().withLoginContext(call, UserRole.Holder)
        val holder = model.loginContexts[UserRole.Holder] as LoginContext
        if (holder.hasAuthToken) {
            model["walletName"] = holder.walletInfo.name
            model["walletDid"] = holder.didInfo.did
            model["walletUri"] = "${walletSvc.endpointUri}/${holder.targetId}"
        }
        return model
    }

    suspend fun showHome(call: RoutingCall, ctx: LoginContext?) {
        val model = walletModel(call, ctx)
        call.respond(
            FreeMarkerContent("wallet_home.ftl", model)
        )
    }

    suspend fun showLoginPage(call: RoutingCall) {
        val model = walletModel(call)
        call.respond(
            FreeMarkerContent("wallet_login.ftl", model)
        )
    }

    suspend fun handleLogin(call: RoutingCall) {
        val params = call.receiveParameters()
        val email = params["email"] ?: error("No email")
        val password = params["password"] ?: error("No password")
        val loginParams = LoginParams(LoginType.EMAIL, email, password)
        SessionsStore.createLoginContext(call, UserRole.Holder, loginParams)
        call.respondRedirect("/wallet")
    }

    suspend fun handleLogout(call: RoutingCall, ctx: LoginContext) {
        SessionsStore.logout(call, ctx.targetId)
        call.respondRedirect("/wallet")
    }

    /**
     * /wallet/auth/callback/${targetId}
     */
    suspend fun handleAuthCallback(call: RoutingCall, ctx: LoginContext) {

        log.info { "Authorization Callback: ${call.request.uri}" }
        urlQueryToMap(call.request.uri).entries.forEach { (k, v) -> log.info { "  $k=$v" } }

        val authCode = getAuthCodeFromRedirectUrl(call.request.uri)

        // [TODO] Do we really always want to fetch the credential in the auth callback
        val accessToken = walletSvc.getAccessTokenFromAuthorizationCode(ctx, authCode)
        val credJwt = walletSvc.getCredential(ctx, accessToken)
        return call.respondRedirect("/wallet/credential/${credJwt.vcId}")
    }

    suspend fun handleAuthFlow(call: RoutingCall, ctx: LoginContext, flowStep: String) {
        when (flowStep) {
            "vp-token-consent" -> handleVPTokenConsent(call, ctx)
            else -> error("Unknown flow step: $flowStep")
        }
    }

    suspend fun handleAuthorization(call: RoutingCall, ctx: LoginContext) {

        val queryParams = urlQueryToMap(call.request.uri)
        val authRequest = AuthorizationRequestDraft11.fromHttpParameters(queryParams)

        when (authRequest.responseType) {

            // Issuer creates IDToken AuthorizationRequest (response_type=id_token, response_mode=direct_post)
            // Note, this may come in with request_uri

            "id_token" -> {
                log.info { "Wallet receives IDToken AuthorizationRequest: ${call.request.uri}" }
                queryParams.entries.forEach { (k, v) -> log.info { "  $k=$v" } }

                val idTokenJwt = walletSvc.createIDToken(ctx, authRequest)
                authorizationSvc.sendIDToken(ctx, authRequest, idTokenJwt)
                call.respondText(
                    status = HttpStatusCode.Accepted,
                    contentType = ContentType.Text.Plain,
                    text = "Accepted"
                )
            }

            "vp_token" -> {
                log.info { "Wallet receives VPToken AuthorizationRequest: ${call.request.uri}" }
                queryParams.entries.forEach { (k, v) -> log.info { "  $k=$v" } }

                handleVPTokenRequest(call, ctx)
            }

            else -> error{ "Unknown AuthorizationRequest: ${call.request.uri}" }
        }
    }

    suspend fun handleAuthorizationMetadataRequest(call: RoutingCall, ctx: LoginContext) {
        val walletTargetUri = "${walletSvc.endpointUri}/${ctx.targetId}"
        val payload = Json.encodeToString(authorizationSvc.buildAuthorizationMetadata(walletTargetUri))
        call.respondText(
            status = HttpStatusCode.OK,
            contentType = ContentType.Application.Json,
            text = payload
        )
    }

    suspend fun handleCredentialOfferAccept(call: RoutingCall, ctx: LoginContext, offerId: String) {

        // Load the Credential Offer from storage
        //
        val credOffer = walletSvc.getCredentialOffer(ctx, offerId)
            ?: error("No credential_offer for: $offerId")

        // Accept a Credential Offer from EBSI CT
        //
        if (credOffer.credentialIssuer == KNOWN_ISSUER_EBSI_V3) {
            val authContext = ctx.createAuthContext().withCredentialOffer(credOffer)
            call.request.queryParameters["userPin"]?.also {
                authContext.putAttachment(USER_PIN_ATTACHMENT_KEY, it)
            }
            val credJwt = walletSvc.getCredentialFromOffer(ctx, credOffer)
            return showCredentialDetails(call, ctx, credJwt.vcId)
        }

        // Accept a Credential Offer from Keycloak
        //
        val authContext = ctx.createAuthContext().withCredentialOffer(credOffer)
        if (credOffer.isPreAuthorized) {
            val credJwt = walletSvc.getCredentialFromOffer(ctx, credOffer)
            return showCredentialDetails(call, ctx, credJwt.vcId)
        }

        val redirectUri = "${requireWalletConfig().callbackUri}/${ctx.targetId}"
        val authEndpointUrl = authContext.getAuthorizationMetadata().getAuthorizationEndpointUri()
        val authRequest = walletSvc.buildAuthorizationRequest(authContext, redirectUri = redirectUri)
        val authRequestUrl = authRequest.toRequestUrl(authEndpointUrl)
        log.info { "Wallet sends AuthorizationRequest: $authRequestUrl" }
        authRequest.toRequestParameters().forEach { (k, v) -> log.info { "  $k=$v" } }

        call.respondRedirect(authRequestUrl)
    }

    suspend fun handleCredentialOfferDelete(call: RoutingCall, ctx: LoginContext, offerId: String) {
        walletSvc.deleteCredentialOffer(ctx, offerId)
        call.respondRedirect("/wallet/credential-offers")
    }

    suspend fun handleCredentialOfferDeleteAll(call: RoutingCall, ctx: LoginContext) {
        walletSvc.deleteCredentialOffers(ctx) { true }
        call.respondRedirect("/wallet/credential-offers")
    }

    suspend fun handleCredentialOfferReceive(call: RoutingCall, ctx: LoginContext) {

        var credOfferJson = call.request.queryParameters["credential_offer"]
        val credOfferUri = call.request.queryParameters["credential_offer_uri"]

        if (credOfferUri != null) {

            log.info { "Received CredentialOfferUri: $credOfferUri" }
            val credOfferUriRes = http.get(credOfferUri)

            credOfferJson = credOfferUriRes.bodyAsText()
            if (credOfferUriRes.status.value !in 200..202) {
                error("Error sending credential Offer: ${credOfferUriRes.status.value} - $credOfferJson")
            }
        }

        requireNotNull(credOfferJson) { "No credential_offer" }

        log.info { "Received CredentialOffer: $credOfferJson" }
        val credOffer = CredentialOffer.fromJson(credOfferJson)

        if (Features.isEnabled(CREDENTIAL_OFFER_STORE)) {
            walletSvc.addCredentialOffer(ctx, credOffer)
        }
        if (Features.isEnabled(CREDENTIAL_OFFER_AUTO_FETCH)) {
            val credJwt = walletSvc.getCredentialFromOffer(ctx, credOffer)
            call.respondText(
                status = HttpStatusCode.Accepted,
                contentType = ContentType.Application.Json,
                text = "${credJwt.toJson()}"
            )
        } else {
            call.respondRedirect("${walletSvc.endpointUri}/credential-offers")
        }
    }

    suspend fun handleCredentialDelete(call: RoutingCall, ctx: LoginContext, vcId: String) {
        walletSvc.deleteCredential(ctx, vcId)
        call.respondRedirect("/wallet/credentials")
    }

    suspend fun handleCredentialDeleteAll(call: RoutingCall, ctx: LoginContext) {
        walletSvc.deleteCredentials(ctx) { true }
        call.respondRedirect("/wallet/credentials")
    }

    suspend fun handleVPTokenRequest(call: RoutingCall, ctx: LoginContext) {

        val reqParams = urlQueryToMap(call.request.uri)

        // Final Qualification Credential use case ...
        //
        //  - EBSI offers the CTWalletQualificationCredential
        //  - Holder sends an AuthorizationRequest, EBSI responds with an 302 Redirect (WalletService.sendAuthorizationRequest)
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
            authContext.putAttachment(AUTH_REQUEST_ATTACHMENT_KEY, authRequest)
            return call.respondRedirect("/wallet/${ctx.targetId}/flow/vp-token-consent?state=ask")
        }
    }

    suspend fun handleVPTokenConsent(call: RoutingCall, ctx: LoginContext) {

        when (val state = call.parameters["state"]) {
            "ask" -> run {
                val authReq = ctx.getAttachment(AUTH_REQUEST_ATTACHMENT_KEY) as AuthorizationRequestV0
                val model = walletModel(call, ctx).also {
                    it["dcqlQuery"] = jsonPretty.encodeToString(authReq.dcqlQuery!!.toJsonObj())
                    it["targetId"] = ctx.targetId
                }
                call.respond(
                    FreeMarkerContent("wallet_vp_ask.ftl", model)
                )
            }

            "accept" -> {
                val authReq = ctx.removeAttachment(AUTH_REQUEST_ATTACHMENT_KEY) as AuthorizationRequestV0
                val authRes = walletSvc.handleVPTokenRequest(ctx, authReq)
                when (authReq.responseMode) {
                    "direct_post" -> run {
                        val res = http.post(authReq.responseUri!!) {
                            contentType(ContentType.Application.Json)
                            setBody(Json.encodeToString(authRes))
                        }

                        val resBody = res.bodyAsText()
                        if (res.status != HttpStatusCode.OK)
                            throw HttpStatusException(res.status, resBody)

                        val resObj = Json.decodeFromString<JsonObject>(resBody)
                        val redirectUri = resObj.getValue("redirect_uri").jsonPrimitive.content

                        call.respondRedirect(redirectUri)
                    }

                    else -> error("Unsupported response_mode: ${authReq.responseMode}")
                }
            }

            "reject" -> 
                throw HttpStatusException(HttpStatusCode.ExpectationFailed, "VPToken Request rejected")
            
            else -> error("Undefined flow state: $state")
        }
    }

    suspend fun showAuthConfig(call: RoutingCall, ctx: LoginContext) {
        val walletTargetUri = "${walletSvc.endpointUri}/${ctx.targetId}"
        val authConfig = authorizationSvc.buildAuthorizationMetadata(walletTargetUri)
        val prettyJson = jsonPretty.encodeToString(authConfig)
        val authConfigUrl = "$walletTargetUri/.well-known/openid-configuration"
        val model = walletModel(call).also {
            it["authConfigJson"] = prettyJson
            it["authConfigUrl"] = authConfigUrl
        }
        call.respond(
            FreeMarkerContent("wallet_auth_config.ftl", model)
        )
    }

    suspend fun showCredentialOfferDetails(call: RoutingCall, ctx: LoginContext, offerId: String) {
        val credOffer = walletSvc.getCredentialOffer(ctx, offerId)
        val prettyJson = jsonPretty.encodeToString(credOffer)
        val isUserPinRequired = call.request.queryParameters["isUserPinRequired"] ?: "false"
        val defaultUserPin = requireEbsiConfig().preAuthUserPin ?: "1234"
        val model = walletModel(call, ctx).also {
            it["credOffer"] = prettyJson
            it["credOfferId"] = offerId
            it["isUserPinRequired"] = isUserPinRequired
            it["defaultUserPin"] = defaultUserPin
        }
        call.respond(
            FreeMarkerContent("wallet_cred_offer.ftl", model)
        )
    }

    suspend fun showCredentialOffers(call: RoutingCall, ctx: LoginContext) {
        val credOfferData = walletSvc.getCredentialOffers(ctx)
            .map { (k, v) ->
                listOf(
                    urlEncode(k),
                    v.credentialIssuer,
                    v.filteredConfigurationIds.first(),
                    "${v.isPreAuthorized}",
                    "${v.isUserPinRequired}",
                )
            }.toList()

        val model = walletModel(call, ctx).also {
            it["credentialOffers"] = credOfferData
            it["userDid"] = ctx.did
            it["credentialOfferEndpoint"] = "${requireEbsiConfig().baseUrl}/wallet/${ctx.targetId}"
        }

        call.respond(
            FreeMarkerContent("wallet_cred_offers.ftl", model)
        )
    }

    suspend fun showCredentialDetails(call: RoutingCall, ctx: LoginContext, vcId: String) {

        val credJwt = walletSvc.getCredentialById(ctx, vcId) ?: error("No credential for: $vcId")
        val jsonObj = when (credJwt) {
            is W3CCredentialV11Jwt -> credJwt.toJson()
            is W3CCredentialSdV11Jwt -> buildJsonObject {
                credJwt.toJson().forEach { (k, v) -> put(k, v) }
                put("jti", JsonPrimitive(credJwt.vcId))
                put("disclosures", Json.decodeFromString(Json.encodeToString(credJwt.disclosures)))
            }
        }
        val prettyJson = jsonPretty.encodeToString(jsonObj)
        val model = walletModel(call, ctx).also {
            it["credId"] = urlEncode(credJwt.vcId)
            it["credData"] = prettyJson
        }
        call.respond(
            FreeMarkerContent("wallet_cred_detail.ftl", model)
        )
    }

    suspend fun showCredentials(call: RoutingCall, ctx: LoginContext) {

        fun abbreviatedDid(did: String) = when {
            did.length > 32 -> "${did.take(20)}...${did.substring(did.length - 12)}"
            else -> did
        }

        val credentialList = walletSvc.findCredentials(ctx) { true }.map { wc ->
            val credJwt = W3CCredentialJwt.fromEncoded(wc.document)
            when (credJwt) {
                is W3CCredentialV11Jwt -> {
                    val vc = credJwt.vc
                    listOf(credJwt.vcId.encodeURLPath(), abbreviatedDid(vc.issuer.id), "${vc.type}")
                }

                is W3CCredentialSdV11Jwt -> {
                    listOf(
                        credJwt.vcId.encodeURLPath(),
                        abbreviatedDid(credJwt.iss ?: "unknown"),
                        credJwt.vct ?: "unknown"
                    )
                }
            }
        }
        val model = walletModel(call, ctx).also {
            it["credentials"] = credentialList
        }
        call.respond(
            FreeMarkerContent("wallet_credentials.ftl", model)
        )
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
     * For every InputDescriptor iterate over all CredentialAccessService and match all constraints.
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

    override suspend fun createCredentialOffer(
        configId: String,
        clientId: String?,
        preAuthorized: Boolean,
        userPin: String?,
        targetUser: User?,
    ): CredentialOffer {
        error("Not available on Wallet")
    }
}