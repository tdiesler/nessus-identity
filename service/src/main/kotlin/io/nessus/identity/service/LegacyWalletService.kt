package io.nessus.identity.service

import io.nessus.identity.AuthorizationContext
import io.nessus.identity.Legacy
import io.nessus.identity.LoginContext
import io.nessus.identity.types.AuthorizationRequestV0
import io.nessus.identity.types.DCQLQuery
import io.nessus.identity.types.SubmissionBundle
import io.nessus.identity.types.TokenResponse

// LegacyWalletService =================================================================================================

interface LegacyWalletService {

    @Legacy
    @Deprecated("promote or remove")
    suspend fun buildAuthorizationRequest(
        authContext: AuthorizationContext,
        clientId: String,
        redirectUri: String = "urn:ietf:wg:oauth:2.0:oob"
    ): AuthorizationRequestV0

    @Legacy
    @Deprecated("promote or remove")
    suspend fun buildPresentationSubmission(
        ctx: LoginContext,
        dcql: DCQLQuery,
    ): SubmissionBundle

    @Legacy
    @Deprecated("promote or remove")
    suspend fun getAuthorizationCode(
        ctx: LoginContext,
        clientId: String,
        username: String,
        password: String,
        redirectUri: String = "urn:ietf:wg:oauth:2.0:oob"
    ): String

    /**
     * The Authorization Request parameter contains a DCQL query that describes the requirements of the Credential(s) that the Verifier is requesting to be presented.
     * Such requirements could include what type of Credential(s), in what format(s), which individual Claims within those Credential(s) (Selective Disclosure), etc.
     * The Wallet processes the Request Object and determines what Credentials are available matching the Verifier's request.
     * The Wallet also authenticates the End-User and gathers their consent to present the requested Credentials.
     *
     * The Wallet prepares the Presentation(s) of the Credential(s) that the End-User has consented to.
     * It then sends to the Verifier an Authorization Response where the Presentation(s) are contained in the vp_token parameter.
     *
     * https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-3
     */
    @Legacy
    @Deprecated("promote or remove")
    suspend fun handleVPTokenRequest(ctx: LoginContext, authReq: AuthorizationRequestV0): TokenResponse
}