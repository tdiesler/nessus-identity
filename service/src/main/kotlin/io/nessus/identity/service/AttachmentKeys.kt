package io.nessus.identity.service

import com.nimbusds.jwt.SignedJWT
import id.walt.oid4vc.data.OpenIDProviderMetadata
import id.walt.oid4vc.requests.AuthorizationRequest
import io.nessus.identity.waltid.DidInfo
import io.nessus.identity.waltid.WalletInfo

object AttachmentKeys {

    // LoginContext
    //
    val AUTH_TOKEN_ATTACHMENT_KEY = attachmentKey<String>("AUTH_TOKEN")
    val WALLET_INFO_ATTACHMENT_KEY = attachmentKey<WalletInfo>()
    val DID_INFO_ATTACHMENT_KEY = attachmentKey<DidInfo>()

    // OIDCContext
    //
    val ACCESS_TOKEN_ATTACHMENT_KEY = attachmentKey<SignedJWT>("ACCESS_TOKEN")
    val AUTH_CODE_ATTACHMENT_KEY = attachmentKey<String>("AUTH_CODE")
    val AUTH_REQUEST_ATTACHMENT_KEY = attachmentKey<AuthorizationRequest>()
    val AUTH_REQUEST_CODE_VERIFIER_ATTACHMENT_KEY = attachmentKey<String>("AUTH_CODE_VERIFIER")
    val OIDC_METADATA_ATTACHMENT_KEY = attachmentKey<OpenIDProviderMetadata>()
}