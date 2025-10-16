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
import io.nessus.identity.extend.signWithKey
import io.nessus.identity.extend.verifyJwtSignature
import io.nessus.identity.types.AuthorizationRequestV10
import io.nessus.identity.types.AuthorizationResponseV10
import io.nessus.identity.types.DCQLQuery
import io.nessus.identity.waltid.authenticationId
import kotlinx.serialization.json.Json
import java.util.*
import kotlin.time.Clock
import kotlin.time.Duration.Companion.minutes
import kotlin.uuid.Uuid

// WalletService =======================================================================================================

class WalletAuthServiceMock(val walletSvc: WalletServiceKeycloak) : WalletAuthService {

    val log = KotlinLogging.logger {}

    override suspend fun authenticate(
        ctx: LoginContext,
        authReq: AuthorizationRequestV10
    ): AuthorizationResponseV10 {

        log.info { "VPToken AuthorizationRequest: ${Json.encodeToString(authReq)}" }

        val dcql = authReq.dcqlQuery ?: error("No dcql_query in: $authReq")
        log.info { "VPToken DCQLQuery: ${dcql.toJson()}" }

        val clientId = authReq.clientId
        val nonce = authReq.nonce
        val state = authReq.state

        val jti = "${Uuid.random()}"
        val iat = Clock.System.now()
        val exp = iat + 5.minutes // 5 mins expiry

        val kid = ctx.didInfo.authenticationId()
        val vpTokenHeader = JWSHeader.Builder(JWSAlgorithm.ES256)
            .type(JOSEObjectType.JWT)
            .keyID(kid)
            .build()

        val vpJson = """{
            "@context": [ "https://www.w3.org/2018/credentials/v1" ],
            "id": "$jti",
            "type": [ "VerifiablePresentation" ],
            "holder": "${ctx.did}",
            "verifiableCredential": []
        }"""
        val vpObj = JSONObjectUtils.parse(vpJson)

        @Suppress("UNCHECKED_CAST")
        val vcArray = vpObj["verifiableCredential"] as MutableList<String>

        val descriptorMappings = mutableListOf<DescriptorMapping>()
        findCredentialsByDCQLQuery(ctx, dcql).forEach { wc ->
            val n = vcArray.size
            val dm = DescriptorMapping(
                path = "unknown",
                format = VCFormat.jwt_vp,
                pathNested = DescriptorMapping(
                    path = "$.vp.verifiableCredential[$n]",
                    format = VCFormat.jwt_vc,
                )
            )
            descriptorMappings.add(dm)
            vcArray.add(wc.document)
        }

        val vpSubmission = PresentationSubmission(
            id = "${Uuid.random()}",
            definitionId = "unknown",
            descriptorMap = descriptorMappings
        )

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

    private suspend fun findCredentialsByDCQLQuery(ctx: LoginContext, dcql: DCQLQuery): List<WalletCredential> {
        val matcher = CredentialMatcherV10()
        val res = walletSvc.findCredentials(ctx) {
            matcher.matchCredential(it, dcql)
        }.onEach {
            log.info { "Matched: ${it.parsedDocument}" }
        }.toList()
        return res
    }
}

