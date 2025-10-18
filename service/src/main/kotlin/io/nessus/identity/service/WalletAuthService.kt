package io.nessus.identity.service

import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.util.JSONObjectUtils
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import id.walt.oid4vc.data.CredentialFormat
import id.walt.oid4vc.data.dif.DescriptorMapping
import id.walt.oid4vc.data.dif.PresentationSubmission
import id.walt.w3c.utils.VCFormat
import id.walt.webwallet.db.models.WalletCredential
import io.github.oshai.kotlinlogging.KotlinLogging
import io.nessus.identity.extend.signWithKey
import io.nessus.identity.extend.verifyJwtSignature
import io.nessus.identity.types.AuthorizationRequestV10
import io.nessus.identity.types.AuthorizationResponseV10
import io.nessus.identity.types.DCQLQuery
import io.nessus.identity.types.QueryClaim
import io.nessus.identity.types.VCDataJwt
import io.nessus.identity.types.VCDataSdV11Jwt
import io.nessus.identity.types.VCDataV11Jwt
import io.nessus.identity.waltid.authenticationId
import kotlinx.serialization.json.Json
import java.util.*
import kotlin.time.Clock
import kotlin.time.Duration.Companion.minutes
import kotlin.uuid.Uuid

// WalletService =======================================================================================================

class WalletAuthService(val walletSvc: WalletServiceKeycloak) {

    val log = KotlinLogging.logger {}

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
    suspend fun authenticate(
        ctx: LoginContext,
        authReq: AuthorizationRequestV10
    ): AuthorizationResponseV10 {

        log.info { "VPToken AuthorizationRequest: ${Json.encodeToString(authReq)}" }

        val clientId = authReq.clientId
        val nonce = authReq.nonce
        val state = authReq.state

        val dcql = authReq.dcqlQuery ?: error("No dcql_query in: $authReq")
        log.info { "VPToken DCQLQuery: ${dcql.toJson()}" }

        // Build the list of Credentials and associated PresentationSubmission
        //
        val (vcJwts, vpSubmission) = buildPresentationSubmission(ctx, dcql)

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
            "verifiableCredential": ${vcJwts.map { "\"${it.serialize()}\"" }}
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

        return AuthorizationResponseV10(vpToken, vpSubmission)
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
                // [TODO #1276] Cannot parse WalletCredential document for sd_jwt_dc
                // https://github.com/walt-id/waltid-identity/issues/1276
                format = if(wc.format == CredentialFormat.sd_jwt_dc) VCFormat.sd_jwt_vc else VCFormat.valueOf(wc.format.value),
                path = "$.vp.verifiableCredential[$n]",
            )
            val vcJwt = VCDataJwt.fromEncoded(wc.document)
            val sigJwt = when(vcJwt) {
                is VCDataV11Jwt -> SignedJWT.parse(wc.document)
                is VCDataSdV11Jwt -> {
                    if (claims == null || claims.isEmpty()) {
                        SignedJWT.parse(wc.document)
                    } else {
                        val parts = mutableListOf(wc.document.substringBefore("~"))
                        val claimMap = vcJwt.disclosureToDigests().associate { (disc, digest) -> disc.claim to digest }
                        val digests = claims.map { cl ->
                            require(cl.path.size == 1) { "Invalid path in: $cl" }
                            claimMap[cl.path[0]] ?: error("No digest for: $cl")
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

    data class SubmissionBundle(
        val credentials: List<SignedJWT>,
        val submission: PresentationSubmission
    )
}

