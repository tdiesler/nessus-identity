package io.nessus.identity.service

import id.walt.webwallet.db.models.WalletCredential
import io.nessus.identity.types.AuthorizationRequestV10
import io.nessus.identity.types.AuthorizationResponseV10
import io.nessus.identity.types.CredentialOffer
import io.nessus.identity.types.VCDataJwt

// WalletService =======================================================================================================

interface WalletAuthService {

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
    suspend fun authenticate(ctx: LoginContext, authReq: AuthorizationRequestV10): AuthorizationResponseV10

}
