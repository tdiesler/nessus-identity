package io.nessus.identity.console

import id.walt.oid4vc.data.CredentialFormat
import id.walt.oid4vc.data.CredentialSupported
import id.walt.oid4vc.data.DisplayProperties
import id.walt.oid4vc.data.GrantType
import id.walt.oid4vc.data.OpenIDProviderMetadata
import id.walt.oid4vc.data.SubjectType
import io.github.oshai.kotlinlogging.KotlinLogging
import io.ktor.http.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import io.ktor.util.*
import io.nessus.identity.config.ConfigProvider.requireEbsiConfig
import io.nessus.identity.config.User
import io.nessus.identity.service.AuthorizationService
import io.nessus.identity.service.CredentialOfferRegistry.hasCredentialOfferRecord
import io.nessus.identity.service.CredentialOfferRegistry.isEBSIPreAuthorizedType
import io.nessus.identity.service.CredentialOfferRegistry.putCredentialOfferRecord
import io.nessus.identity.service.LoginContext
import io.nessus.identity.types.CredentialOffer
import io.nessus.identity.types.IssuerMetadataDraft11
import io.nessus.identity.types.TokenRequest
import io.nessus.identity.waltid.publicKeyJwk
import kotlinx.serialization.json.*

abstract class AuthHandler(val authorizationSvc: AuthorizationService) {

    val log = KotlinLogging.logger {}

    val jsonPretty = Json { prettyPrint = true }

    abstract val endpointUri: String

    abstract suspend fun createCredentialOffer(
        configId: String,
        clientId: String? = null,
        preAuthorized: Boolean = false,
        userPin: String? = null,
        targetUser: User? = null,
    ): CredentialOffer

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

    open suspend fun handleTokenRequest(call: RoutingCall, ctx: LoginContext) {

        val postParams = call.receiveParameters().toMap().toMutableMap()
        log.info { "Token Request: ${call.request.uri}" }
        postParams.forEach { (k, lst) -> lst.forEach { v -> log.info { "  $k=$v" } } }

        val preAuthCode = postParams["pre-authorized_code"]?.firstOrNull()
        if (preAuthCode != null && isEBSIPreAuthorizedType(preAuthCode)) {

            // [TODO] remove on-demand CredentialOffer creation
            // In the EBSI Issuer Conformance Test, the preAuthCode is a known Credential type
            // and the clientId associated with the TokenRequest is undefined

            val ebsiConfig = requireEbsiConfig()
            val clientId = ebsiConfig.requesterDid as String
            postParams["client_id"] = listOf(clientId)

            // Issuing CredentialOffers (on-demand) for EBSI Conformance
            if (!hasCredentialOfferRecord(preAuthCode)) {
                val userPin = postParams["user_pin"]?.firstOrNull()
                log.info { "Issuing CredentialOffer $preAuthCode (on-demand) for EBSI Conformance" }
                val credOffer = createCredentialOffer(preAuthCode, clientId, preAuthorized = true, userPin = userPin)
                putCredentialOfferRecord(preAuthCode, credOffer, userPin)
            }
        }

        val tokenRequest = TokenRequest.fromHttpParameters(postParams)
        val tokenResponse = authorizationSvc.getTokenResponse(ctx, tokenRequest)

        call.respondText(
            status = HttpStatusCode.OK,
            contentType = ContentType.Application.Json,
            text = Json.encodeToString(tokenResponse)
        )
    }

    // Protected -------------------------------------------------------------------------------------------------------

    protected fun getIssuerMetadataDraft11(ctx: LoginContext): IssuerMetadataDraft11 {
        val issuerTargetUrl = "$endpointUri/${ctx.targetId}"
        val credentialSupported = mapOf(
            "CTWalletSameAuthorisedInTime" to CredentialSupported(
                format = CredentialFormat.jwt_vc,
                display = listOf(DisplayProperties(locale = "en-GB", name = "CTWalletSameAuthorisedInTime")),
                types = listOf("VerifiableCredential", "VerifiableAttestation", "CTWalletSameAuthorisedInTime")
            ),
            "CTWalletSameAuthorisedDeferred" to CredentialSupported(
                format = CredentialFormat.jwt_vc,
                display = listOf(DisplayProperties(locale = "en-GB", name = "CTWalletSameAuthorisedDeferred")),
                types = listOf("VerifiableCredential", "VerifiableAttestation", "CTWalletSameAuthorisedDeferred")
            ),
            "CTWalletSamePreAuthorisedInTime" to CredentialSupported(
                format = CredentialFormat.jwt_vc,
                display = listOf(DisplayProperties(locale = "en-GB", name = "CTWalletSamePreAuthorisedInTime")),
                types = listOf("VerifiableCredential", "VerifiableAttestation", "CTWalletSamePreAuthorisedInTime")
            ),
            "CTWalletSamePreAuthorisedDeferred" to CredentialSupported(
                format = CredentialFormat.jwt_vc,
                display = listOf(DisplayProperties(locale = "en-GB", name = "CTWalletSamePreAuthorisedDeferred")),
                types = listOf("VerifiableCredential", "VerifiableAttestation", "CTWalletSamePreAuthorisedDeferred")
            ),
        )
        val waltDraft11 = OpenIDProviderMetadata.Draft11.create(
            issuer = issuerTargetUrl,
            authorizationServer = issuerTargetUrl,
            authorizationEndpoint = "$issuerTargetUrl/authorize",
            pushedAuthorizationRequestEndpoint = "$issuerTargetUrl/par",
            tokenEndpoint = "$issuerTargetUrl/token",
            credentialEndpoint = "$issuerTargetUrl/credential",
            batchCredentialEndpoint = "$issuerTargetUrl/batch_credential",
            deferredCredentialEndpoint = "$issuerTargetUrl/credential_deferred",
            jwksUri = "$issuerTargetUrl/jwks",
            grantTypesSupported = setOf(GrantType.authorization_code, GrantType.pre_authorized_code),
            requestUriParameterSupported = true,
            subjectTypesSupported = setOf(SubjectType.public),
            credentialIssuer = issuerTargetUrl,
            responseTypesSupported = setOf(
                "code",
                "vp_token",
                "id_token"
            ),
            idTokenSigningAlgValuesSupported = setOf("ES256"),
            codeChallengeMethodsSupported = listOf("S256"),
            credentialSupported = credentialSupported,
        )
        val metadata = IssuerMetadataDraft11.fromJson(waltDraft11.toJSONString())
        return metadata
    }

    // Private ---------------------------------------------------------------------------------------------------------

}
