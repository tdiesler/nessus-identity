package io.nessus.identity.service

import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.util.Base64URL
import com.nimbusds.jose.util.JSONObjectUtils
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import id.walt.oid4vc.OpenID4VCI
import id.walt.oid4vc.data.CredentialFormat
import id.walt.oid4vc.data.dif.DescriptorMapping
import id.walt.oid4vc.data.dif.PresentationSubmission
import id.walt.oid4vc.requests.AuthorizationRequest
import id.walt.oid4vc.requests.CredentialRequest
import id.walt.oid4vc.requests.TokenRequest
import id.walt.oid4vc.responses.CredentialResponse
import id.walt.oid4vc.responses.TokenResponse
import id.walt.w3c.utils.VCFormat
import io.ktor.client.*
import io.ktor.client.plugins.contentnegotiation.*
import io.ktor.client.request.*
import io.ktor.client.request.forms.*
import io.ktor.client.statement.*
import io.ktor.http.*
import io.ktor.serialization.kotlinx.json.*
import io.nessus.identity.config.ConfigProvider.authEndpointUri
import io.nessus.identity.extend.signWithKey
import io.nessus.identity.extend.toSignedJWT
import io.nessus.identity.extend.verifyJwtSignature
import io.nessus.identity.service.AttachmentKeys.ACCESS_TOKEN_ATTACHMENT_KEY
import io.nessus.identity.service.AttachmentKeys.AUTH_CODE_ATTACHMENT_KEY
import io.nessus.identity.service.AttachmentKeys.AUTH_REQUEST_ATTACHMENT_KEY
import io.nessus.identity.service.AttachmentKeys.AUTH_REQUEST_CODE_VERIFIER_ATTACHMENT_KEY
import io.nessus.identity.service.AttachmentKeys.PRESENTATION_SUBMISSION_ATTACHMENT_KEY
import io.nessus.identity.service.AttachmentKeys.REQUEST_URI_OBJECT_ATTACHMENT_KEY
import io.nessus.identity.service.CredentialOfferRegistry.assertCredentialOfferRecord
import io.nessus.identity.types.AuthorizationRequestBuilder
import io.nessus.identity.types.CredentialOffer
import io.nessus.identity.types.CredentialOfferDraft11
import io.nessus.identity.types.CredentialOfferDraft17
import io.nessus.identity.types.IssuerMetadataDraft11
import io.nessus.identity.types.W3CCredentialJwt
import io.nessus.identity.waltid.WaltIDServiceProvider.widWalletSvc
import io.nessus.identity.waltid.authenticationId
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import java.time.Instant
import java.util.*
import kotlin.random.Random
import kotlin.uuid.ExperimentalUuidApi
import kotlin.uuid.Uuid

// WalletServiceDraft17 ===============================================================================================

class WalletServiceDraft17(ctx: OIDContext) : AbstractWalletService<CredentialOfferDraft17>(ctx) {


// Private ------------------------------------------------------------------------------------------------------------

}