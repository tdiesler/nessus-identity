package io.nessus.identity.service

import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.util.JSONObjectUtils
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import id.walt.oid4vc.data.dif.DescriptorMapping
import id.walt.oid4vc.data.dif.PresentationSubmission
import id.walt.w3c.utils.VCFormat
import id.walt.webwallet.db.models.WalletCredential
import io.github.oshai.kotlinlogging.KotlinLogging
import io.ktor.client.request.*
import io.ktor.client.request.forms.*
import io.ktor.client.statement.*
import io.ktor.http.*
import io.nessus.identity.config.ConfigProvider.requireWalletConfig
import io.nessus.identity.extend.signWithKey
import io.nessus.identity.extend.verifyJwtSignature
import io.nessus.identity.service.AuthorizationContext.Companion.EBSI32_AUTH_CODE_ATTACHMENT_KEY
import io.nessus.identity.service.AuthorizationContext.Companion.EBSI32_AUTH_REQUEST_ATTACHMENT_KEY
import io.nessus.identity.service.LoginContext.Companion.AUTH_CONTEXT_ATTACHMENT_KEY
import io.nessus.identity.types.AuthorizationRequest
import io.nessus.identity.types.DCQLQuery
import io.nessus.identity.types.QueryClaim
import io.nessus.identity.types.TokenResponse
import io.nessus.identity.types.W3CCredentialJwt
import io.nessus.identity.types.W3CCredentialSdV11Jwt
import io.nessus.identity.types.W3CCredentialV11Jwt
import io.nessus.identity.waltid.authenticationId
import kotlinx.serialization.json.*
import java.time.Instant
import java.util.*
import kotlin.time.Clock
import kotlin.time.Duration.Companion.minutes
import kotlin.uuid.Uuid

// WalletAuthorizationService ===================================================================================================

class WalletAuthorizationService(val walletSvc: WalletServiceKeycloak) {

    val log = KotlinLogging.logger {}

    val authEndpointUri = requireWalletConfig().authUri

    fun buildAuthCodeRedirectUri(ctx: LoginContext, authCode: String): String {

        val authContext = ctx.assertAttachment(AUTH_CONTEXT_ATTACHMENT_KEY)
        val authReq = authContext.assertAttachment(EBSI32_AUTH_REQUEST_ATTACHMENT_KEY)
        val authCodeRedirect = URLBuilder("${authReq.redirectUri}").apply {
            parameters.append("code", authCode)
            authReq.state?.also { state ->
                parameters.append("state", state)
            }
        }.buildString()

        AuthServiceEbsi32.Companion.log.info { "AuthCode Redirect: $authCodeRedirect" }
        urlQueryToMap(authCodeRedirect).also {
            it.forEach { (k, v) -> AuthServiceEbsi32.Companion.log.info { "  $k=$v" } }
        }

        return authCodeRedirect
    }

    suspend fun createIDToken(
        ctx: LoginContext,
        reqParams: Map<String, String>
    ): SignedJWT {

        // Verify required query params
        for (key in listOf("client_id", "redirect_uri", "response_type")) {
            reqParams[key] ?: throw IllegalStateException("Cannot find $key")
        }

        // The Wallet answers the ID Token Request by providing the id_token in the redirect_uri as instructed by response_mode of direct_post.
        // The id_token must be signed with the DID document's authentication key.

        val clientId = reqParams["client_id"] as String
        val responseType = reqParams["response_type"] as String

        if (responseType != "id_token")
            throw IllegalStateException("Unexpected response_type: $responseType")

        val nonce = reqParams["nonce"]
        val state = reqParams["state"]

        val iat = Instant.now()
        val exp = iat.plusSeconds(300) // 5 mins expiry

        val kid = ctx.didInfo.authenticationId()

        val idTokenHeader = JWSHeader.Builder(JWSAlgorithm.ES256)
            .type(JOSEObjectType.JWT)
            .keyID(kid)
            .build()

        val jwtBuilder = JWTClaimsSet.Builder()
            .issuer(ctx.did)
            .subject(ctx.did)
            .audience(clientId)
            .issueTime(Date.from(iat))
            .expirationTime(Date.from(exp))
            .claim("nonce", nonce)

        nonce?.also { jwtBuilder.claim("nonce", it) }
        state?.also { jwtBuilder.claim("state", it) }
        val idTokenClaims = jwtBuilder.build()

        val idTokenJwt = SignedJWT(idTokenHeader, idTokenClaims).signWithKey(ctx, kid)
        log.info { "IDToken Header: ${idTokenJwt.header}" }
        log.info { "IDToken Claims: ${idTokenJwt.jwtClaimsSet}" }

        log.info { "IDToken: ${idTokenJwt.serialize()}" }
        idTokenJwt.verifyJwtSignature("IDToken", ctx.didInfo)

        return idTokenJwt
    }

    suspend fun sendIDToken(
        ctx: LoginContext,
        redirectUri: String,
        idTokenJwt: SignedJWT
    ): String {
        val authContext = ctx.assertAttachment(AUTH_CONTEXT_ATTACHMENT_KEY)

        log.info { "Send IDToken: $redirectUri" }
        val formData = mutableMapOf(
            "id_token" to idTokenJwt.serialize(),
        )
        val isTokenClaims = idTokenJwt.jwtClaimsSet
        isTokenClaims.getClaim("state")?.also { formData["state"] = "$it" }

        formData.forEach { (k, v) -> log.info { "  $k=$v" } }

        val res = http.post(redirectUri) {
            contentType(ContentType.Application.FormUrlEncoded)
            setBody(FormDataContent(Parameters.build {
                formData.forEach { (k, v) -> append(k, v) }
            }))
        }

        if (res.status != HttpStatusCode.Found)
            throw HttpStatusException(res.status, res.bodyAsText())

        val location = res.headers["location"]?.also {
            log.info { "IDToken Response: $it" }
        } ?: throw IllegalStateException("Cannot find 'location' in headers")

        val authCode = urlQueryToMap(location)["code"]?.also {
            authContext.putAttachment(EBSI32_AUTH_CODE_ATTACHMENT_KEY, it)
        } ?: throw IllegalStateException("No authorization code")

        return authCode
    }

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
    suspend fun handleVPTokenRequest(ctx: LoginContext, authReq: AuthorizationRequest): TokenResponse {

        log.info { "VPToken AuthorizationRequest: ${Json.encodeToString(authReq)}" }

        val clientId = authReq.clientId
        val nonce = authReq.nonce
        val state = authReq.state

        val dcql = authReq.dcqlQuery ?: error("No dcql_query in: $authReq")
        log.info { "VPToken DCQLQuery: ${dcql.toJson()}" }

        // Build the list of Credentials and associated PresentationSubmission
        //
        val (credJwts, vpSubmission) = buildPresentationSubmission(ctx, dcql)

        // Build the VPToken JWT
        //
        val jti = "${Uuid.random()}"
        val iat = Clock.System.now()
        val exp = iat + 5.minutes // 5 mins expiry

        val kid = ctx.didInfo.authenticationId()
        val vpTokenHeader = JWSHeader.Builder(JWSAlgorithm.ES256)
            .type(JOSEObjectType.JWT)
            .keyID(kid)
            .build()

        // Parse VPToken template with Jose to a MutableMap
        //
        val vpJson = """{
            "@context": [ "https://www.w3.org/2018/credentials/v1" ],
            "id": "$jti",
            "type": [ "VerifiablePresentation" ],
            "holder": "${ctx.did}",
            "verifiableCredential": ${credJwts.map { "\"${it.serialize()}\"" }}
        }"""
        val vpObj = JSONObjectUtils.parse(vpJson)

        val claimsBuilder = JWTClaimsSet.Builder()
            .jwtID(jti)
            .issuer(ctx.did)
            .subject(ctx.did)
            .audience(clientId)
            .issueTime(Date(iat.toEpochMilliseconds()))
            .notBeforeTime(Date(iat.toEpochMilliseconds()))
            .expirationTime(Date(exp.toEpochMilliseconds()))
            .claim("vp", vpObj)

        nonce?.also { claimsBuilder.claim("nonce", it) }
        state?.also { claimsBuilder.claim("state", it) }
        val vpTokenClaims = claimsBuilder.build()

        val vpTokenJwt = SignedJWT(vpTokenHeader, vpTokenClaims).signWithKey(ctx, kid)
        log.info { "VPToken Header: ${vpTokenJwt.header}" }
        log.info { "VPToken Claims: ${vpTokenJwt.jwtClaimsSet}" }

        val vpToken = vpTokenJwt.serialize()
        log.info { "VPToken: $vpToken" }
        log.info { "VPSubmission: ${vpSubmission.toJSON()}" }

        vpTokenJwt.verifyJwtSignature("VPToken", ctx.didInfo)

        return TokenResponse(vpToken = vpToken, presentationSubmission = vpSubmission)
    }

    fun validateIDToken(ctx: LoginContext, idTokenJwt: SignedJWT): String {
        val authContext = ctx.assertAttachment(AUTH_CONTEXT_ATTACHMENT_KEY)

        log.info { "IDToken Header: ${idTokenJwt.header}" }
        log.info { "IDToken Claims: ${idTokenJwt.jwtClaimsSet}" }

        // [TODO #233] Verify IDToken proof DID ownership
        // https://github.com/tdiesler/nessus-identity/issues/233
        // We should be able to use the Holder's public key to do that

        val authCode = "${Uuid.random()}"
        authContext.putAttachment(EBSI32_AUTH_CODE_ATTACHMENT_KEY, authCode)

        val authReq = authContext.assertAttachment(EBSI32_AUTH_REQUEST_ATTACHMENT_KEY)
        val idTokenRedirect = URLBuilder("${authReq.redirectUri}").apply {
            parameters.append("code", authCode)
            authReq.state?.also { state ->
                parameters.append("state", state)
            }
        }.buildString()

        log.info { "IDToken Response $idTokenRedirect" }
        urlQueryToMap(idTokenRedirect).also {
            it.forEach { (k, v) -> log.info { "  $k=$v" } }
        }

        return idTokenRedirect
    }

    // Private -------------------------------------------------------------------------------------------------------------------------------------------------

    private suspend fun buildPresentationSubmission(
        ctx: LoginContext,
        dcql: DCQLQuery,
    ): SubmissionBundle {
        val vcArray = mutableListOf<SignedJWT>()
        val descriptorMappings = mutableListOf<DescriptorMapping>()
        val queryIds = mutableListOf<String>()
        findMatchingCredentials(ctx, dcql).forEach { (wc, queryId, claims) ->
            val n = vcArray.size
            queryIds.add(queryId)
            val dm = DescriptorMapping(
                format = VCFormat.entries.first { it.value == wc.format.value },
                path = "$.vp.verifiableCredential[$n]",
            )
            val credJwt = W3CCredentialJwt.fromEncoded(wc.document)
            val sigJwt = when (credJwt) {
                is W3CCredentialV11Jwt -> SignedJWT.parse(wc.document)
                is W3CCredentialSdV11Jwt -> {
                    if (claims == null || claims.isEmpty()) {
                        SignedJWT.parse(wc.document)
                    } else {
                        val parts = mutableListOf(wc.document.substringBefore("~"))
                        val claimMap = credJwt.disclosures.associateBy { disc -> disc.claim }
                        val digests = claims.map { cl ->
                            require(cl.path.size == 1) { "Invalid path in: $cl" }
                            val encoded = claimMap[cl.path[0]]?.decoded ?: error("No digest for: $cl")
                            base64UrlEncode(encoded.toByteArray())
                        }
                        parts.addAll(digests)
                        SignedJWT.parse(parts.joinToString("~"))
                    }
                }
            }
            descriptorMappings.add(dm)
            vcArray.add(sigJwt)
        }

        // The presentation_submission object **MUST** contain a definition_id property.
        // The value of this property **MUST** be the id value of a valid Presentation Definition.
        // https://identity.foundation/presentation-exchange/#presentation-submission
        //
        // In the absence of a Presentation Definition
        val vpSubmission = PresentationSubmission(
            id = "${Uuid.random()}",
            definitionId = "dcql:${queryIds.joinToString("-")}",
            descriptorMap = descriptorMappings
        )
        return SubmissionBundle(vcArray, vpSubmission)
    }

    private suspend fun findMatchingCredentials(
        ctx: LoginContext,
        dcql: DCQLQuery
    ): List<Triple<WalletCredential, String, List<QueryClaim>?>> {
        val matcher = CredentialMatcherV10()
        val credentials = walletSvc.findCredentials(ctx) { true } // cache all credentials to avoid multiple API calls
        val res = dcql.credentials.mapNotNull { cq ->
            matcher.matchCredential(cq, credentials.asSequence())?.let { (wc, claims) ->
                Triple(wc, cq.id, claims)
            }
        }.onEach {
            log.info { "Matched: ${it.first.parsedDocument}" }
        }
        return res
    }

    private data class SubmissionBundle(
        val credentials: List<SignedJWT>,
        val submission: PresentationSubmission
    )
}

