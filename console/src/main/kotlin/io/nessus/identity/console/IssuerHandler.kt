package io.nessus.identity.console

import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.util.JSONObjectUtils
import com.nimbusds.jwt.JWTClaimNames
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import id.walt.oid4vc.data.CredentialFormat
import id.walt.oid4vc.requests.CredentialRequest
import id.walt.oid4vc.responses.CredentialResponse
import io.ktor.client.request.*
import io.ktor.client.statement.*
import io.ktor.http.*
import io.ktor.server.freemarker.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import io.ktor.util.*
import io.nessus.identity.config.ConfigProvider.requireWalletConfig
import io.nessus.identity.console.SessionsStore.requireLoginContext
import io.nessus.identity.extend.signWithKey
import io.nessus.identity.extend.verifyJwtSignature
import io.nessus.identity.service.AuthorizationContext
import io.nessus.identity.service.AuthorizationContext.Companion.EBSI32_AUTHORIZATION_REQUEST_ATTACHMENT_KEY
import io.nessus.identity.service.IssuerService
import io.nessus.identity.service.LoginContext
import io.nessus.identity.service.LoginContext.Companion.AUTH_CONTEXT_ATTACHMENT_KEY
import io.nessus.identity.service.WalletAuthorizationService.Companion.buildAuthorizationMetadata
import io.nessus.identity.service.http
import io.nessus.identity.types.AuthorizationRequestDraft11
import io.nessus.identity.types.CredentialConfiguration
import io.nessus.identity.types.CredentialOffer
import io.nessus.identity.types.CredentialParameters
import io.nessus.identity.types.CredentialSchema
import io.nessus.identity.types.UserRole
import io.nessus.identity.types.VCDataV11JwtBuilder
import io.nessus.identity.types.W3CCredentialV11Builder
import io.nessus.identity.waltid.Alice
import io.nessus.identity.waltid.Bob
import io.nessus.identity.waltid.LoginType
import io.nessus.identity.waltid.Max
import io.nessus.identity.waltid.RegisterUserParams
import io.nessus.identity.waltid.User
import io.nessus.identity.waltid.WaltIDServiceProvider.widWalletService
import io.nessus.identity.waltid.authenticationId
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.*
import org.keycloak.representations.idm.UserRepresentation
import java.time.Instant
import kotlin.io.encoding.Base64
import kotlin.time.Clock
import kotlin.time.Duration.Companion.hours
import kotlin.uuid.Uuid


class IssuerHandler: AuthHandler() {

    val issuer = Max
    val issuerSvc = IssuerService.createKeycloak()
    val issuerMetadata get() = runBlocking { issuerSvc.getIssuerMetadata() }

    override val endpointUri = issuerSvc.issuerEndpointUri
    
    fun issuerModel(call: RoutingCall, ctx: LoginContext? = null): BaseModel {
        val authServerUrl = issuerMetadata.authorizationServers?.first() ?: error("No AuthorizationServer")
        val authConfigUrl = "$authServerUrl/.well-known/openid-configuration"
        val issuerConfigUrl = issuerSvc.getIssuerMetadataUrl()
        val model = ctx?.let { BaseModel().withLoginContext(ctx) }
            ?: BaseModel().withLoginContext(call, UserRole.Holder)
        model["issuerUrl"] = issuerSvc.issuerBaseUrl
        model["issuerConfigUrl"] = issuerConfigUrl
        model["authConfigUrl"] = authConfigUrl
        return model
    }

    suspend fun showHome(call: RoutingCall) {
        val model = issuerModel(call)
        call.respond(
            FreeMarkerContent("issuer_home.ftl", model)
        )
    }

    suspend fun showAuthConfig(call: RoutingCall) {
        val authConfig = issuerMetadata.getAuthorizationMetadata()
        val prettyJson = jsonPretty.encodeToString(authConfig)
        val model = issuerModel(call).also {
            it["authConfigJson"] = prettyJson
        }
        call.respond(
            FreeMarkerContent("auth_config.ftl", model)
        )
    }

    suspend fun showIssuerConfig(call: RoutingCall) {
        val prettyJson = jsonPretty.encodeToString(issuerMetadata)
        val model = issuerModel(call).also {
            it["issuerConfigJson"] = prettyJson
        }
        call.respond(
            FreeMarkerContent("issuer_config.ftl", model)
        )
    }

    suspend fun handleNativeAuthorizationRequest(call: RoutingCall, ctx: LoginContext) {

        val queryParams = call.parameters.toMap()
        val authRequest = AuthorizationRequestDraft11.fromHttpParameters(queryParams)
        log.info { "Issuer receives Authorization Request: ${Json.encodeToString(authRequest)}" }
        queryParams.forEach { (k, lst) -> lst.forEach { v -> log.info { "  $k=$v" } } }

        val authContext = AuthorizationContext.create(ctx)
        authContext.putAttachment(EBSI32_AUTHORIZATION_REQUEST_ATTACHMENT_KEY, authRequest)
        val idTokenReqJwt = buildIDTokenRequest(ctx, authRequest)
        val authRequestRedirectUri = authRequest.redirectUri as String
        val redirectUrl = buildIDTokenRedirectUrl(authRequestRedirectUri, idTokenReqJwt)
        return call.respondRedirect(redirectUrl)
    }

    suspend fun handleNativeCredentialRequest(call: RoutingCall, ctx: LoginContext) {

        val accessToken = call.request.headers["Authorization"]
            ?.takeIf { it.startsWith("Bearer ", ignoreCase = true) }
            ?.removePrefix("Bearer ")
            ?: throw IllegalArgumentException("Invalid authorization header")

        val credReq = call.receive<CredentialRequest>()
        val accessTokenJwt = SignedJWT.parse(accessToken)
        val credentialResponse = getNativeCredentialFromRequest(ctx, credReq, accessTokenJwt)

        call.respondText(
            status = HttpStatusCode.OK,
            contentType = ContentType.Application.Json,
            text = Json.encodeToString(credentialResponse)
        )
    }

    suspend fun handleNativeCredentialRequestDeferred(call: RoutingCall, ctx: LoginContext) {

        val acceptanceToken = call.request.headers["Authorization"]
            ?.takeIf { it.startsWith("Bearer ", ignoreCase = true) }
            ?.removePrefix("Bearer ")
            ?: throw IllegalArgumentException("Invalid authorization header")

        val acceptanceTokenJwt = SignedJWT.parse(acceptanceToken)
        val credentialResponse = getNativeCredentialFromAcceptanceToken(ctx, acceptanceTokenJwt)

        call.respondText(
            status = HttpStatusCode.OK,
            contentType = ContentType.Application.Json,
            text = Json.encodeToString(credentialResponse)
        )
    }

    suspend fun handleNativeDirectPost(call: RoutingCall, ctx: LoginContext) {

        val postParams = call.receiveParameters().toMap()
        log.info { "Issuer DirectPost: ${call.request.uri}" }
        postParams.forEach { (k, lst) -> lst.forEach { v -> log.info { "  $k=$v" } } }

        if (postParams["id_token"] != null) {
            val idToken = postParams["id_token"]?.first()
            val idTokenJwt = SignedJWT.parse(idToken)
            val authCode = validateIDToken(ctx, idTokenJwt)
            val redirectUrl = buildAuthCodeRedirectUri(ctx, authCode)
            return call.respondRedirect(redirectUrl)
        }

        call.respondText(
            status = HttpStatusCode.InternalServerError,
            contentType = ContentType.Text.Plain,
            text = "Not Implemented"
        )
    }

    suspend fun handleNativeAuthorizationMetadataRequest(call: RoutingCall, ctx: LoginContext) {
        val issuerTargetUri = "${issuerSvc.issuerEndpointUri}/${ctx.targetId}"
        val payload = Json.encodeToString(buildAuthorizationMetadata(issuerTargetUri))
        call.respondText(
            status = HttpStatusCode.OK,
            contentType = ContentType.Application.Json,
            text = payload
        )
    }

    suspend fun handleNativeIssuerMetadataRequest(call: RoutingCall, ctx: LoginContext) {
        val issuerMetadata = IssuerService.createEbsi().getIssuerMetadata(ctx)
        val payload = Json.encodeToString(issuerMetadata)
        call.respondText(
            status = HttpStatusCode.OK,
            contentType = ContentType.Application.Json,
            text = payload
        )
    }

    suspend fun showCredentialConfig(call: RoutingCall, configId: String) {
        val credConfig = issuerMetadata.credentialConfigurationsSupported[configId] as CredentialConfiguration
        val prettyJson = jsonPretty.encodeToString(credConfig.toJsonObj())
        val model = issuerModel(call).also {
            it["configId"] = configId
            it["credConfigJson"] = prettyJson
        }
        call.respond(
            FreeMarkerContent("issuer_cred_config.ftl", model)
        )
    }

    suspend fun showCredentialOfferCreate(call: RoutingCall) {

        val configId = call.request.queryParameters["configId"] ?: error("No configId")
        val users = issuerSvc.getUsers().map { SubjectOption.fromUserRepresentation(it) }

        val model = issuerModel(call).also {
            it["configId"] = configId
            it["users"] = users
        }
        call.respond(
            FreeMarkerContent("issuer_cred_offer_create.ftl", model)
        )
    }

    suspend fun handleCredentialOfferCreate(call: RoutingCall) {

        val params = call.receiveParameters()
        val configId = params["configId"] ?: error("No configId")
        val userId = params["userId"] ?: error("No userId")
        val preAuthorized = params["preAuthorized"].toBoolean()

        val usersMap = listOf(Alice, Bob, Max).associateBy { usr -> usr.email }
        val holder = usersMap[userId]

        val credOfferUri = issuerSvc.createCredentialOfferUri(issuer, configId, preAuthorized, holder)
        val credOfferQRCode = issuerSvc.createCredentialOfferUriQRCode(issuer, configId, preAuthorized, holder)

        val model = issuerModel(call).also {
            it["configId"] = configId
            it["holder"] = holder ?: User("Anonymous", "", "")
            it["credOfferUri"] = credOfferUri
            it["credOfferQRCode"] = Base64.encode(credOfferQRCode)
        }

        call.respond(
            FreeMarkerContent("issuer_cred_offer_send.ftl", model)
        )
    }

    suspend fun handleCredentialOfferSend(call: RoutingCall) {

        val params = call.receiveParameters()
        val credOfferUri = params["credOfferUri"] ?: error("No credOfferUri")

        val holderContext = requireLoginContext(call, UserRole.Holder)
        val targetId = holderContext.targetId

        val credOfferUriRes = http.get(credOfferUri) {}
        val credOffer = CredentialOffer.fromJson(credOfferUriRes.bodyAsText())

        val walletUrl = "${requireWalletConfig().baseUrl}/$targetId"
        val credOfferSendRes = http.get(walletUrl) {
            parameter("credential_offer", credOffer.toJson())
        }
        if (credOfferSendRes.status.value !in 200..202)
            error("Error sending credential Offer: ${credOfferSendRes.status.value} - ${credOfferSendRes.bodyAsText()}")

        call.respondRedirect("/wallet/credential-offers")
    }

    suspend fun showCredentialOffers(call: RoutingCall) {
        val supported = issuerMetadata.credentialConfigurationsSupported
        val model = issuerModel(call).also {
            it["configIds"] = supported.keys
        }
        call.respond(
            FreeMarkerContent("issuer_cred_offers.ftl", model)
        )
    }

    suspend fun showUsers(call: RoutingCall) {
        val users = issuerSvc.getUsers().map { SubjectOption.fromUserRepresentation(it) }
        val model = issuerModel(call).also {
            it["users"] = users
        }
        call.respond(
            FreeMarkerContent("issuer_users.ftl", model)
        )
    }

    suspend fun showCreateUserPage(call: RoutingCall) {
        val model = issuerModel(call)
        call.respond(
            FreeMarkerContent("issuer_user_create.ftl", model)
        )
    }

    suspend fun handleUserCreate(call: RoutingCall) {
        val params = call.receiveParameters()
        val name = params["name"] ?: error("No name")
        val nameParts = name.split(" ")
        require(nameParts.size == 2) { "Expected first and last name" }
        val (firstName, lastName) = Pair(nameParts[0], nameParts[1])
        val email = params["email"] ?: error("No email")
        val username = firstName.lowercase()
        val password = params["password"] ?: error("No password")

        // Register in WaltId (immutable henceforth)
        val userParams = RegisterUserParams(LoginType.EMAIL, name, email, password)
        runCatching {
            widWalletService.authRegister(userParams)
        }.onFailure { ex ->
            if (ex.message?.contains("account with email $email already exists") == true) {
                log.error(ex) { }
            } else {
                throw ex
            }
        }

        // Create in Keycloak (mutable henceforth)
        issuerSvc.createUser(firstName, lastName, email, username, password)
        call.respondRedirect("/issuer/users")
    }

    suspend fun handleUserDelete(call: RoutingCall, userId: String) {
        issuerSvc.deleteUser(userId)
        call.respondRedirect("/issuer/users")
    }

    // Private ---------------------------------------------------------------------------------------------------------

    private suspend fun getNativeCredentialFromRequest(
        ctx: LoginContext,
        credReq: CredentialRequest,
        accessTokenJwt: SignedJWT,
        deferred: Boolean = false
    ): CredentialResponse {

        // Validate the AccessToken
        validateAccessToken(accessTokenJwt)

        log.info { "CredentialRequest: ${Json.encodeToString(credReq)}" }

        // Derive the deferred case from the CredentialRequest type
        //
        val deferredEBSIType = credReq.types?.any { it.startsWith("CT") && it.endsWith("Deferred") } == true
        val credentialResponse = if (deferred || deferredEBSIType) {
            getNativeCredentialFromRequestDeferred(ctx, credReq)
        } else {
            val authContext = ctx.assertAttachment(AUTH_CONTEXT_ATTACHMENT_KEY)
            val authRequest = authContext.assertAttachment(EBSI32_AUTHORIZATION_REQUEST_ATTACHMENT_KEY)
            val params = CredentialParameters()
                .withIssuer(ctx.did)
                .withSubject(authRequest.clientId)
                .withTypes(credReq.types!!)
            getCredentialFromParameters(ctx, params)
        }
        return credentialResponse
    }

    private suspend fun getNativeCredentialFromRequestDeferred(
        ctx: LoginContext,
        credReq: CredentialRequest,
    ): CredentialResponse {

        log.info { "CredentialRequestDeferred: ${Json.encodeToString(credReq)}" }

        requireNotNull(credReq.types) { "No types in CredentialRequest" }

        val metadata = IssuerService.createEbsi().getIssuerMetadata(ctx)
        val supportedCredentials = metadata.credentialsSupported.flatMap { it.types.orEmpty() }.toSet()
        val unknownTypes = credReq.types!!.filterNot { it in supportedCredentials }
        if (unknownTypes.isNotEmpty())
            throw IllegalStateException("Unknown credential types: $unknownTypes")

        val authContext = ctx.assertAttachment(AUTH_CONTEXT_ATTACHMENT_KEY)
        val authRequest = authContext.assertAttachment(EBSI32_AUTHORIZATION_REQUEST_ATTACHMENT_KEY)

        val jti = "vc:nessus#${Uuid.random()}"
        val sub = authRequest.clientId
        val nbf = Instant.now().plusSeconds(5)

        val kid = ctx.didInfo.authenticationId()
        val acceptanceHeader = JWSHeader.Builder(JWSAlgorithm.ES256)
            .type(JOSEObjectType.JWT)
            .keyID(kid)
            .build()

        val acceptanceClaims = JWTClaimsSet.parse(
            mapOf(
                JWTClaimNames.JWT_ID to jti,
                JWTClaimNames.ISSUER to ctx.did,
                JWTClaimNames.SUBJECT to sub,
                JWTClaimNames.NOT_BEFORE to nbf.epochSecond,
                "credential_request" to Json.encodeToString(credReq)
            )
        )

        val acceptanceTokenJwt = SignedJWT(acceptanceHeader, acceptanceClaims).signWithKey(ctx, kid)
        log.info { "AcceptanceToken Header: ${acceptanceTokenJwt.header}" }
        log.info { "AcceptanceToken Claims: ${acceptanceTokenJwt.jwtClaimsSet}" }

        acceptanceTokenJwt.verifyJwtSignature("AcceptanceToken", ctx.didInfo)

        val credentialResponse = CredentialResponse.deferred(CredentialFormat.jwt_vc, acceptanceTokenJwt.serialize())
        log.info { "CredentialResponseDeferred: ${Json.encodeToString(credentialResponse)}" }

        return credentialResponse
    }

    private suspend fun getNativeCredentialFromAcceptanceToken(
        ctx: LoginContext,
        acceptanceTokenJwt: SignedJWT
    ): CredentialResponse {

        // Validate the AcceptanceTokenJwt
        // [TODO #241] Validate the AcceptanceToken
        // https://github.com/tdiesler/nessus-identity/issues/241

        // Derive the deferred case from the CredentialRequestV0 type
        //
        log.info { "AcceptanceToken Header: ${acceptanceTokenJwt.header}" }
        log.info { "AcceptanceToken Claims: ${acceptanceTokenJwt.jwtClaimsSet}" }

        val authContext = ctx.assertAttachment(AUTH_CONTEXT_ATTACHMENT_KEY)
        val authRequest = authContext.assertAttachment(EBSI32_AUTHORIZATION_REQUEST_ATTACHMENT_KEY)

        val credReqJson = acceptanceTokenJwt.jwtClaimsSet.getClaim("credential_request") as String
        val credReq = Json.decodeFromString<CredentialRequest>(credReqJson)
        val params = CredentialParameters()
            .withIssuer(ctx.did)
            .withSubject(authRequest.clientId)
            .withTypes(credReq.types!!)
        val credentialResponse = getCredentialFromParameters(ctx, params)

        return credentialResponse
    }

    private suspend fun getCredentialFromParameters(
        ctx: LoginContext,
        vcp: CredentialParameters
    ): CredentialResponse {

        // Init property defaults when not given
        //
        val id = vcp.id ?: "vc:nessus#${Uuid.random()}"
        val iat = vcp.iat ?: Clock.System.now()
        val nbf = vcp.nbf ?: iat
        val exp = vcp.exp ?: (iat + 24.hours)
        val iss = vcp.iss ?: ctx.did

        // Verify required properties
        //
        val sub = vcp.sub ?: throw java.lang.IllegalStateException("No subject")
        if (vcp.types.isEmpty())
            throw java.lang.IllegalStateException("No types")

        // Verify credential types i.e. every type must bve known to this issuer
        val metadata = IssuerService.createEbsi().getIssuerMetadata(ctx)
        val supportedCredentials = metadata.credentialsSupported.flatMap { it.types.orEmpty() }.toSet()
        val unknownTypes = vcp.types.filterNot { it in supportedCredentials }
        if (unknownTypes.isNotEmpty())
            throw IllegalStateException("Unknown credential types: $unknownTypes")

        val cred = VCDataV11JwtBuilder()
            .withId(id)
            .withIssuerId(ctx.did)
            .withSubjectId(vcp.sub as String)
            .withIssuedAt(iat)
            .withValidFrom(nbf)
            .withValidUntil(exp)
            .withCredential(
                W3CCredentialV11Builder()
                    .withCredentialSchema(
                        CredentialSchema(
                            "https://api-conformance.ebsi.eu/trusted-schemas-registry/v3/schemas/zDpWGUBenmqXzurskry9Nsk6vq2R8thh9VSeoRqguoyMD",
                            "FullJsonSchemaValidator2021"
                        )
                    )
                    .withId(id)
                    .withIssuer(iss)
                    .withCredentialStatus(vcp.status)
                    .withCredentialSubject(sub)
                    .withIssuedAt(iat)
                    .withValidFrom(nbf)
                    .withValidUntil(exp)
                    .withTypes(vcp.types)
                    .build()
            )
            .build()

        val kid = ctx.didInfo.authenticationId()
        val credHeader = JWSHeader.Builder(JWSAlgorithm.ES256)
            .type(JOSEObjectType.JWT)
            .keyID(kid)
            .build()

        val credJson = Json.encodeToString(cred)
        val credClaims = JWTClaimsSet.parse(JSONObjectUtils.parse(credJson))

        val credJwt = SignedJWT(credHeader, credClaims).signWithKey(ctx, kid)
        log.info { "Credential Header: ${credJwt.header}" }
        log.info { "Credential Claims: ${credJwt.jwtClaimsSet}" }

        credJwt.verifyJwtSignature("Credential", ctx.didInfo)

        val credRes = CredentialResponse.success(CredentialFormat.jwt_vc, credJwt.serialize())
        log.info { "CredentialResponse: ${Json.encodeToString(credRes)}" }

        return credRes
    }

    private fun validateAccessToken(bearerToken: SignedJWT) {

        val claims = bearerToken.jwtClaimsSet
        val exp = claims.expirationTime?.toInstant()
        if (exp == null || exp.isBefore(Instant.now()))
            throw IllegalStateException("Token expired")

        // [TODO #235] Properly validate the AccessToken
        // https://github.com/tdiesler/nessus-identity/issues/235
    }
}

data class SubjectOption(
    val id: String,
    val name: String,
    val email: String,
) {
    companion object {
        fun fromUserRepresentation(it: UserRepresentation): SubjectOption {
            return SubjectOption(it.id, "${it.firstName} ${it.lastName}", it.email)
        }
    }
}
