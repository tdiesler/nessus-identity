package io.nessus.identity.service

import com.nimbusds.jose.util.Base64URL
import io.nessus.identity.service.AttachmentKeys.AUTH_REQUEST_ATTACHMENT_KEY
import io.nessus.identity.service.AttachmentKeys.AUTH_REQUEST_CODE_VERIFIER_ATTACHMENT_KEY
import io.nessus.identity.service.AuthServiceEbsi32.Companion.authEndpointUri
import io.nessus.identity.types.AuthorizationRequestDraft11Builder
import io.nessus.identity.types.CredentialParameters
import io.nessus.identity.types.PresentationDefinitionBuilder
import io.nessus.identity.types.VCDataV11Jwt
import io.nessus.identity.waltid.WaltIDServiceProvider.widWalletService
import kotlin.random.Random

class CredentialVerificationFlowEbsi32(val holderCtx: OIDContext, val verifierCtx: OIDContext) {

    val authSvc = AuthServiceEbsi32.create(verifierCtx)
    val walletSvc = WalletService.createEbsi()
    val verifierSvc = VerifierService.createEbsi()

    /**
     * Holder finds Credential by Type and presents it to the Verifier
     */
    suspend fun verifyPresentationByType(ctype: String) {
        
        // Holder queries it's Wallet to find the requested Credential
        //
        val vcFound = widWalletService.findCredentialsByType(holderCtx, ctype)
        if (vcFound.isEmpty())
            throw IllegalStateException("$ctype not found")

        // The Holder sends an AuthorizationRequest to the Verifier
        //
        val rndBytes = Random.nextBytes(32)
        val codeVerifier = Base64URL.encode(rndBytes).toString()

        val redirectUri = "$authEndpointUri/${holderCtx.targetId}"
        val authRequest = AuthorizationRequestDraft11Builder()
            .withClientId(holderCtx.did)
            .withClientState(holderCtx.walletId)
            .withCodeChallengeMethod("S256")
            .withCodeVerifier(codeVerifier)
            .withPresentationDefinition(PresentationDefinitionBuilder()
                .withInputDescriptorForType(ctype, id = "inp#1")
                .build())
            .withRedirectUri(redirectUri)
            .build()

        holderCtx.putAttachment(AUTH_REQUEST_ATTACHMENT_KEY, authRequest)
        holderCtx.putAttachment(AUTH_REQUEST_CODE_VERIFIER_ATTACHMENT_KEY, codeVerifier)

        // The Verifier sends a VPToken Request to the Holder (request of VerifiablePresentation)
        //
        authSvc.validateAuthorizationRequest(authRequest)
        val vpTokenRequestJwt = authSvc.buildVPTokenRequest(authRequest)
        val vpTokenRedirectUrl = authSvc.buildVPTokenRedirectUrl(vpTokenRequestJwt)
        val vpTokenRequestParams = urlQueryToMap(vpTokenRedirectUrl)

        if (vpTokenRequestParams["client_id"] != holderCtx.did)
            throw IllegalStateException("Unexpected client_id: ${vpTokenRequestParams["client_id"]}")

        if (vpTokenRequestParams["response_mode"] != "direct_post")
            throw IllegalStateException("Unexpected response_mode: ${vpTokenRequestParams["response_mode"]}")

        if (vpTokenRequestParams["response_type"] != "vp_token")
            throw IllegalStateException("Unexpected response_type: ${vpTokenRequestParams["response_type"]}")

        // Holder responds with a signed VPToken that contains the VerifiablePresentation
        //
        val vpTokenJwt = walletSvc.createVPToken(holderCtx, authRequest)

        // Verifier validates the VPToken
        //
        val vpHolder = CredentialMatcher.pathValues(vpTokenJwt, "$.vp.holder").first()
        if (vpHolder != holderCtx.did)
            throw IllegalStateException("Unexpected holder id: $vpHolder")

        // Verifier validates the Credential
        //
        val vpCred = CredentialMatcher.pathValues(vpTokenJwt, "$.vp.verifiableCredential").first()
        val vpcJwt = VCDataV11Jwt.fromEncoded(vpCred)

        val vcp = CredentialParameters()
            .withSubject(holderCtx.did)
            .withTypes(listOf(ctype))

        verifierSvc.validateVerifiableCredential(vpcJwt, vcp)
    }
}