package io.nessus.identity.service

import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.JWSObject
import com.nimbusds.jose.crypto.ECDSAVerifier
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.util.Base64URL
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import id.walt.oid4vc.data.CredentialFormat
import io.ktor.client.request.*
import io.ktor.client.statement.*
import io.ktor.http.*
import io.nessus.identity.config.ConfigProvider
import io.nessus.identity.extend.signWithKey
import io.nessus.identity.types.*
import io.nessus.identity.waltid.WaltIDServiceProvider.widDidService
import io.nessus.identity.waltid.WaltIDServiceProvider.widWalletService
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonPrimitive
import java.time.Instant
import java.util.*
import kotlin.random.Random

// WalletServiceKeycloak =======================================================================================================================================

class WalletServiceKeycloak : AbstractWalletService<CredentialOfferV10>() {

    val clientId = ConfigProvider.requireIssuerConfig().clientId

    /**
     * Holder builds the AuthorizationRequest from a CredentialOffer
     */
    suspend fun authContextForCredential(
        ctx: LoginContext,
        redirectUri: String,
        credOffer: CredentialOfferV10,
    ): AuthorizationContext {

        // Resolve the Issuer's metadata from the CredentialOffer
        val metadata = credOffer.resolveIssuerMetadata() as IssuerMetadataV10

        val rndBytes = Random.nextBytes(32)
        val codeVerifier = Base64URL.encode(rndBytes).toString()

        val authRequest = buildAuthorizationRequest(redirectUri, credOffer, codeVerifier)

        val authContext = AuthorizationContext(ctx)
            .withIssuerMetadata(metadata)
            .withCredentialOffer(credOffer)
            .withCodeVerifier(codeVerifier)
            .withAuthorizationRequest(authRequest)

        return authContext
    }

    /**
     * Holder gets a Credential from an Issuer based on a CredentialOffer
     * https://hub.ebsi.eu/conformance/build-solutions/issue-to-holder-functional-flows#in-time-issuance
     */
    suspend fun credentialFromOfferInTime(ctx: AuthorizationContext): VCDataJwt {

        val credOffer = ctx.credOffer ?: error("No Credential Offer")

        // Holder sends a TokenRequest to obtain an AccessToken
        // https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-token-request
        val tokenRes = sendTokenRequest(ctx)
        log.info { "AccessToken: ${tokenRes.accessToken}" }

        // Holder sends a CredentialRequest
        //
        val credRes = sendCredentialRequest(OIDContext(ctx), credOffer, tokenRes)

        val vcJwt = validateAndStoreCredential(ctx, credRes)

        return vcJwt
    }

    // Private -------------------------------------------------------------------------------------------------------------------------------------------------

    private suspend fun buildAuthorizationRequest(
        redirectUri: String,
        credOffer: CredentialOfferV10,
        codeVerifier: String? = null
    ): AuthorizationRequestV10 {

        val builder = AuthorizationRequestV10Builder()
            .withRedirectUri(redirectUri)
            .withClientId(clientId)

        if (codeVerifier != null) {
            builder.withCodeChallengeMethod("S256")
            builder.withCodeVerifier(codeVerifier)
        }

        val authReq = builder.buildFrom(credOffer)
        return authReq
    }

    private suspend fun sendTokenRequest(ctx: AuthorizationContext): TokenResponseV10 {

        val authReq = ctx.authRequest
        val metadata = ctx.metadata
        val authCode = ctx.authCode ?: error("No Auth Code")
        val codeVerifier = ctx.codeVerifier ?: error("No Code Verifier")

        val tokenEndpointUrl = metadata.getAuthorizationTokenEndpoint()

        val tokenReq = TokenRequestV10.AuthorizationCode(
            clientId = clientId,
            redirectUri = authReq.redirectUri,
            codeVerifier = codeVerifier,
            code = authCode
        )

        val res = http.post(tokenEndpointUrl) {
            contentType(ContentType.Application.FormUrlEncoded)
            setBody(
                Parameters.build {
                    append("grant_type", "authorization_code")
                    append("client_id", tokenReq.clientId)
                    append("code", tokenReq.code)
                    append("redirect_uri", tokenReq.redirectUri!!)
                    append("code_verifier", tokenReq.codeVerifier!!) // when using PKCE
                }.formUrlEncode()
            )
        }
        val tokenResJson = res.bodyAsText()
        log.info { "TokenResponse: $tokenResJson" }
        if (res.status != HttpStatusCode.OK)
            throw HttpStatusException(res.status, tokenResJson)

        val tokenRes = TokenResponseV10.fromJson(tokenResJson)
        return tokenRes
    }

    private suspend fun sendCredentialRequest(
        ctx: LoginContext,
        credOffer: CredentialOfferV10,
        tokenRes: TokenResponseV10
    ): CredentialResponseV10 {

        val metadata: IssuerMetadataV10 = credOffer.resolveIssuerMetadata()

        val ctypes = credOffer.credentialConfigurationIds
        if (ctypes.size != 1) throw IllegalArgumentException("Multiple types not supported: $ctypes")
        val ctype = ctypes.first()

        val cNonce = tokenRes.cNonce ?: let {
            val res = http.post(metadata.nonceEndpoint!!)
            if (res.status != HttpStatusCode.OK)
                throw HttpStatusException(res.status, res.bodyAsText())
            val jsonObj = Json.decodeFromString<JsonObject>(res.bodyAsText())
            jsonObj.getValue("c_nonce").jsonPrimitive.content
        }

        val kid = ctx.didInfo.keyId
        val ecKeyJson = widWalletService.exportKey(ctx, kid)
        val publicJwk = JWK.parse(ecKeyJson) as ECKey
        log.info { "PublicJwk: $publicJwk" }

        val proofHeader = JWSHeader.Builder(JWSAlgorithm.ES256)
            .type(JOSEObjectType("openid4vci-proof+jwt"))
            .jwk(publicJwk) // embed JWK directly
            .build()

        val iat = Instant.now()
        val exp = iat.plusSeconds(300) // 5 mins expiry
        val proofClaims = JWTClaimsSet.Builder()
            .audience(credOffer.credentialIssuer)
            .issueTime(Date.from(iat))
            .expirationTime(Date.from(exp))
            .claim("nonce", cNonce)
            .build()

        val proofJwt = SignedJWT(proofHeader, proofClaims).signWithKey(ctx, kid)
        log.info { "ProofHeader: ${proofJwt.header}" }
        log.info { "ProofClaims: ${proofJwt.jwtClaimsSet}" }

        val credReq = CredentialRequestV10(
            credentialConfigurationId = ctype,
            proofs = CredentialRequestV10.Proofs(jwt = listOf(proofJwt.serialize()))
        )

        log.info { "CredentialRequest: ${Json.encodeToString(credReq)}" }

        val res = http.post(metadata.credentialEndpoint) {
            header(HttpHeaders.Authorization, "Bearer ${tokenRes.accessToken}")
            contentType(ContentType.Application.Json)
            setBody(credReq)
        }
        val credResJson = res.bodyAsText()
        if (res.status != HttpStatusCode.OK)
            throw HttpStatusException(res.status, credResJson)

        log.info { "CredentialResponse: $credResJson" }
        val credRes = CredentialResponseV10.fromJson(credResJson)

        return credRes
    }

    private suspend fun validateAndStoreCredential(
        ctx: AuthorizationContext,
        credRes: CredentialResponseV10
    ): VCDataJwt {

        // Extract the VerifiableCredentials from the CredentialResponse
        //
        val credJwts = credRes.credentials?.map { SignedJWT.parse(it.credential) }.orEmpty()
        if (credJwts.isEmpty()) error("No credential in response")
        if (credJwts.size > 1) error("Multiple credentials not supported")

        val credJwt = credJwts[0]
        log.info { "CredentialJwt Header: ${credJwt.header}" }
        log.info { "CredentialJwt Claims: ${credJwt.jwtClaimsSet}" }

        val vcJwt = Json.decodeFromString<VCDataJwt>("${credJwt.payload}")
        log.info { "Credential: ${vcJwt.toJson()}" }

        val ctype = when (vcJwt) {
            is VCDataV11Jwt -> {
                if (vcJwt.vc.type.size != 1) error("Multiple types not supported")
                vcJwt.vc.type.first()
            }
            is VCDataSdV11Jwt -> {
                vcJwt.vct ?: error("No vct")
            }
        }
        val credConfig = ctx.metadata.credentialConfigurationsSupported[ctype] ?: error("No credential_configurations_supported for: $ctype")
        val format = CredentialFormat.fromValue(credConfig.format) as CredentialFormat

        // Resolve issuer DID
        val issuerDid = credJwt.jwtClaimsSet.issuer
        log.info { "Issuer Did: $issuerDid" }

        // Resolve DID Document locally
        val key = widDidService.resolveToKey(issuerDid).getOrThrow()
        val jwk = JWK.parse("${key.exportJWKObject()}")
        log.info { "Issuer Jwk: $jwk" }

        val ecdsaVerifier = ECDSAVerifier(jwk.toECKey())
        when (vcJwt) {
            is VCDataV11Jwt -> {
                check(credJwt.verify(ecdsaVerifier)) { "Invalid credential signature" }
            }
            is VCDataSdV11Jwt -> {
                val combined = "${credJwt.serialize()}"
                val jwsCompact = combined.substringBefore('~')  // keep only JWS
                val jwsObj = JWSObject.parse(jwsCompact)
                check(jwsObj.verify(ecdsaVerifier)) { "Invalid credential signature" }
            }
        }

        // Validate JWT standard claims
        credJwt.jwtClaimsSet.run {
            val now = Date()
            check(notBeforeTime == null || !now.before(notBeforeTime)) { "Credential not yet valid" }
            check(expirationTime == null || !now.after(expirationTime)) { "Credential expired" }
            check(issuer == issuerDid) { "Issuer mismatch" }
        }

        // Add Credential to WaltId storage
        //
        val walletId = ctx.walletId
        widWalletService.addCredential(walletId, format, credJwt)

        return vcJwt
    }

}