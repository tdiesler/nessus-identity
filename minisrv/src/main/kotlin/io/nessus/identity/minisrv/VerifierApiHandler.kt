package io.nessus.identity.minisrv

import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.util.JSONObjectUtils
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import io.ktor.http.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import io.nessus.identity.AuthorizationContext.Companion.EBSI32_AUTHORIZATION_REQUEST_DRAFT11_ATTACHMENT_KEY
import io.nessus.identity.LoginContext
import io.nessus.identity.config.ConfigProvider.requireEbsiConfig
import io.nessus.identity.service.VerifierService
import io.nessus.identity.types.AuthorizationRequestDraft11
import io.nessus.identity.types.PresentationDefinitionBuilder
import io.nessus.identity.types.UserRole
import io.nessus.identity.types.publicKeyJwk
import io.nessus.identity.utils.signWithKey
import io.nessus.identity.utils.urlQueryToMap
import kotlinx.serialization.json.*
import java.time.Instant
import java.util.*
import kotlin.uuid.Uuid

class VerifierApiHandler(val verifierSvc: VerifierService):
    AuthorizationApiHandler(UserRole.Verifier, verifierSvc.authorizationSvc) {

    suspend fun handleAuthorize(call: RoutingCall, ctx: LoginContext) {

        val queryParams = urlQueryToMap(call.request.uri)
        val authRequest = AuthorizationRequestDraft11.fromHttpParameters(queryParams)

        val responseType = authRequest.responseType
        val scopes = authRequest.scope?.split(" ") ?: listOf()

        when (responseType) {
            "code" -> {
                when {
                    scopes.any { it.contains("id_token") } -> {
                        val authContext = ctx.createAuthContext()
                        val queryParams = urlQueryToMap(call.request.uri)

                        val authRequestIn = AuthorizationRequestDraft11.fromHttpParameters(queryParams)
                        authContext.putAttachment(EBSI32_AUTHORIZATION_REQUEST_DRAFT11_ATTACHMENT_KEY, authRequestIn)

                        val targetEndpointUri = "$endpointUri/${ctx.targetId}"
                        val redirectUri = requireNotNull(authRequestIn.redirectUri) { "No redirect_uri" }
                        val idTokenRequestJwt = authorizationSvc.createIDTokenRequestJwt(ctx, targetEndpointUri, authRequestIn)
                        val authRequestOut = authorizationSvc.createIDTokenAuthorizationRequest(redirectUri, idTokenRequestJwt)
                        return call.respondRedirect(authRequestOut.toRequestUrl(redirectUri))
                    }
                    scopes.any { it.contains("vp_token") } -> {
                        val authContext = ctx.createAuthContext()
                        val queryParams = urlQueryToMap(call.request.uri)
                        val authRequest = AuthorizationRequestDraft11.fromHttpParameters(queryParams)
                        authContext.putAttachment(EBSI32_AUTHORIZATION_REQUEST_DRAFT11_ATTACHMENT_KEY, authRequest)
                        val vpTokenReqJwt = buildVPTokenRequest(ctx, authRequest)
                        val redirectUrl = buildVPTokenRedirectUrl(ctx, authRequest, vpTokenReqJwt)
                        return call.respondRedirect(redirectUrl)
                    }
                    else -> {
                        return call.respondText(
                            status = HttpStatusCode.Accepted,
                            contentType = ContentType.Text.Plain,
                            text = "Accepted"
                        )
                    }
                }
            }
            else -> {
                call.respondText(
                    status = HttpStatusCode.InternalServerError,
                    contentType = ContentType.Text.Plain,
                    text = "Unknown AuthorizationRequest"
                )
            }
        }
    }

    // Private ---------------------------------------------------------------------------------------------------------

    private suspend fun buildVPTokenRequest(ctx: LoginContext, authReq: AuthorizationRequestDraft11): SignedJWT {

        val requesterDid = requireEbsiConfig().requesterDid
        val targetEndpointUri = "$endpointUri/${ctx.targetId}"

        val keyJwk = ctx.didInfo.publicKeyJwk()
        val kid = keyJwk["kid"]?.jsonPrimitive?.content as String

        val iat = Instant.now()
        val exp = iat.plusSeconds(300) // 5 mins expiry

        val vpTokenHeader = JWSHeader.Builder(JWSAlgorithm.ES256).type(JOSEObjectType.JWT).keyID(kid).build()

        val presentationDefinition = authReq.presentationDefinition ?: run {

            require(authReq.scope?.contains("vp_token") ?: false) { "No PresentationDefinition" }

            // EBSI wants exactly three InputDescriptor(s)
            // Authorization endpoint's response doesn't contain a valid JWT payload in the VP Token request
            // Validation error. Path: 'presentation_definition.input_descriptors'. Reason: Array must contain exactly 3 element(s)
            PresentationDefinitionBuilder().withInputDescriptorForType("VerifiableAttestation")
                .withInputDescriptorForType("VerifiableAttestation").withInputDescriptorForType("VerifiableAttestation")
                .build()
        }

        val presentationDefinitionJson = Json.encodeToString(presentationDefinition)
        log.info { "PresentationDefinition: $presentationDefinitionJson" }

        val vpTokenClaims =
            JWTClaimsSet.Builder().issuer(requesterDid).audience(authReq.clientId)
                .issueTime(Date.from(iat)).expirationTime(Date.from(exp)).claim("response_type", "vp_token")
                .claim("response_mode", "direct_post")
                .claim("client_id", requesterDid)
                .claim("redirect_uri", "$targetEndpointUri/direct_post")
                .claim("scope", authReq.scope)
                .claim("nonce", "${Uuid.random()}")
                .claim("presentation_definition", JSONObjectUtils.parse(presentationDefinitionJson)).build()

        val vpTokenReqJwt = SignedJWT(vpTokenHeader, vpTokenClaims).signWithKey(ctx, kid)
        log.info { "VPTokenRequest Header: ${vpTokenReqJwt.header}" }
        log.info { "VPTokenRequest Claims: ${vpTokenReqJwt.jwtClaimsSet}" }

        return vpTokenReqJwt
    }

    private fun buildVPTokenRedirectUrl(ctx: LoginContext, authReq: AuthorizationRequestDraft11, vpTokenReqJwt: SignedJWT): String {

        requireNotNull(authReq.scope) { "No scope" }
        val targetEndpointUri = "$endpointUri/${ctx.targetId}"

        // Is VPTokenRequest payload an AuthorizationRequestV0?
        // https://github.com/tdiesler/nessus-identity/issues/226
        val vpTokenRedirectUrl = URLBuilder("${authReq.redirectUri}").apply {
            parameters.append("client_id", authReq.clientId) // Holder Did
            parameters.append("response_type", "vp_token")
            parameters.append("response_mode", "direct_post")
            parameters.append("scope", authReq.scope!!)
            parameters.append("redirect_uri", "$targetEndpointUri/direct_post")
            // [TODO #227] May need to use request_uri for VPToken Request redirect url
            // https://github.com/tdiesler/nessus-identity/issues/227
            parameters.append("request", "${vpTokenReqJwt.serialize()}")
        }.buildString()

        log.info { "VPToken Redirect $vpTokenRedirectUrl" }
        urlQueryToMap(vpTokenRedirectUrl).also {
            it.forEach { (k, v) -> log.info { "  $k=$v" } }
        }

        return vpTokenRedirectUrl
    }

}
