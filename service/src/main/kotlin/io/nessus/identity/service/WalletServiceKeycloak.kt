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
import io.nessus.identity.service.LoginContext.Companion.AUTH_CONTEXT_ATTACHMENT_KEY
import io.nessus.identity.types.AuthorizationRequest
import io.nessus.identity.types.AuthorizationRequestBuilder
import io.nessus.identity.types.CredentialOfferV10
import io.nessus.identity.types.CredentialRequestV0
import io.nessus.identity.types.CredentialResponseV0
import io.nessus.identity.types.IssuerMetadataV10
import io.nessus.identity.types.TokenRequest
import io.nessus.identity.types.TokenResponseV0
import io.nessus.identity.types.VCDataJwt
import io.nessus.identity.types.VCDataSdV11Jwt
import io.nessus.identity.types.VCDataV11Jwt
import io.nessus.identity.waltid.WaltIDServiceProvider.widDidService
import io.nessus.identity.waltid.WaltIDServiceProvider.widWalletService
import kotlinx.serialization.json.*
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

        val authContext = AuthorizationContext()
            .withIssuerMetadata(metadata)
            .withCredentialOffer(credOffer)
            .withCodeVerifier(codeVerifier)
            .withAuthorizationRequest(authRequest)

        ctx.putAttachment(AUTH_CONTEXT_ATTACHMENT_KEY, authContext)

        return authContext
    }

    fun sendAuthenticationRequest(ctx: LoginContext, username: String, password: String): String {

        val authContext = ctx.assertAttachment(AUTH_CONTEXT_ATTACHMENT_KEY)

        val authReq = authContext.authRequest
        val authEndpointUrl = authContext.authEndpointUrl

        val authCode = OAuthClient()
            .withLoginCredentials(username, password)
            .sendAuthorizationRequest(authEndpointUrl, authReq)

        authContext.authCode = authCode
        return authCode
    }

    /**
     * Holder gets a Credential from an Issuer based on a CredentialOffer
     * https://hub.ebsi.eu/conformance/build-solutions/issue-to-holder-functional-flows#in-time-issuance
     */
    suspend fun credentialFromOfferInTime(ctx: LoginContext): VCDataJwt {

        val authContext = ctx.getAttachment(AUTH_CONTEXT_ATTACHMENT_KEY) as AuthorizationContext
        val credOffer = authContext.credOffer ?: error("No Credential Offer")

        // Holder sends a TokenRequest to obtain an AccessToken
        // https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-token-request
        val tokRes = sendTokenRequest(authContext)
        log.info { "AccessToken: ${tokRes.accessToken}" }

        // Holder sends a CredentialRequest
        //
        val credRes = sendCredentialRequest(ctx, credOffer, tokRes)

        val vcJwt = validateAndStoreCredential(ctx, credRes)

        return vcJwt
    }

    // Private -------------------------------------------------------------------------------------------------------------------------------------------------

    private suspend fun buildAuthorizationRequest(
        redirectUri: String,
        credOffer: CredentialOfferV10,
        codeVerifier: String? = null
    ): AuthorizationRequest {

        val builder = AuthorizationRequestBuilder()
            .withRedirectUri(redirectUri)
            .withClientId(clientId)

        if (codeVerifier != null) {
            builder.withCodeChallengeMethod("S256")
            builder.withCodeVerifier(codeVerifier)
        }

        val authReq = builder.buildFrom(credOffer)
        return authReq
    }

    private suspend fun sendTokenRequest(authContext: AuthorizationContext): TokenResponseV0 {

        val authReq = authContext.authRequest
        val metadata = authContext.issuerMetadata
        val authCode = authContext.authCode ?: error("No Auth Code")
        val codeVerifier = authContext.codeVerifier ?: error("No Code Verifier")

        val tokenEndpointUrl = metadata.getAuthorizationTokenEndpoint()

        val tokReq = TokenRequest.AuthorizationCode(
            clientId = clientId,
            redirectUri = authReq.redirectUri,
            codeVerifier = codeVerifier,
            code = authCode
        )

        val tokRes = OAuthClient().sendTokenRequest(tokenEndpointUrl, tokReq)
        log.info { "TokenResponse: ${tokRes.toJson()}" }
        return tokRes
    }

    private suspend fun sendCredentialRequest(
        ctx: LoginContext,
        credOffer: CredentialOfferV10,
        tokenRes: TokenResponseV0
    ): CredentialResponseV0 {

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

        val credReq = CredentialRequestV0(
            credentialConfigurationId = ctype,
            proofs = CredentialRequestV0.Proofs(jwt = listOf(proofJwt.serialize()))
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
        val credRes = CredentialResponseV0.fromJson(credResJson)

        return credRes
    }

    private suspend fun validateAndStoreCredential(
        ctx: LoginContext,
        credRes: CredentialResponseV0
    ): VCDataJwt {

        // Extract the VerifiableCredentials from the CredentialResponse
        //
        val sigJwts = credRes.credentials?.map { SignedJWT.parse(it.credential) }.orEmpty()
        if (sigJwts.isEmpty()) error("No credential in response")
        if (sigJwts.size > 1) error("Multiple credentials not supported")

        val sigJwt = sigJwts[0]
        log.info { "CredentialJwt Header: ${sigJwt.header}" }
        log.info { "CredentialJwt Claims: ${sigJwt.jwtClaimsSet}" }

        val vcJwt = VCDataJwt.fromEncoded("${sigJwt.serialize()}")
        log.info { "Credential: ${vcJwt.toJson()}" }

        val ctype = when (vcJwt) {
            is VCDataV11Jwt -> {
                vcJwt.vc.type.first {
                    !listOf("VerifiableAttestation", "VerifiableCredential").contains(it)
                }
            }
            is VCDataSdV11Jwt -> {
                vcJwt.vct ?: error("No vct")
            }
        }
        val authContext = ctx.removeAttachment(AUTH_CONTEXT_ATTACHMENT_KEY) as AuthorizationContext
        val credConfig = authContext.issuerMetadata.credentialConfigurationsSupported[ctype] ?: error("No credential_configurations_supported for: $ctype")
        val format = CredentialFormat.fromValue(credConfig.format) as CredentialFormat

        // Resolve issuer
        val issuerId = sigJwt.jwtClaimsSet.issuer
        log.info { "IssuerId: $issuerId" }

        // [TODO #331] Verify VC signature when iss is not did:key:*
        // https://github.com/tdiesler/nessus-identity/issues/331
        when {
            issuerId.startsWith("did:key:") -> {

                // Resolve DID Document locally
                val key = widDidService.resolveToKey(issuerId).getOrThrow()
                val jwk = JWK.parse("${key.exportJWKObject()}")
                log.info { "Issuer Jwk: $jwk" }

                val ecdsaVerifier = ECDSAVerifier(jwk.toECKey())
                when (vcJwt) {
                    is VCDataV11Jwt -> {
                        check(sigJwt.verify(ecdsaVerifier)) { "Invalid credential signature" }
                    }
                    is VCDataSdV11Jwt -> {
                        val combined = "${sigJwt.serialize()}"
                        val jwsCompact = combined.substringBefore('~')  // keep only JWS
                        val jwsObj = JWSObject.parse(jwsCompact)
                        check(jwsObj.verify(ecdsaVerifier)) { "Invalid credential signature" }
                    }
                }
            }
        }

        // Validate JWT standard claims
        sigJwt.jwtClaimsSet.run {
            val now = Date()
            check(notBeforeTime == null || !now.before(notBeforeTime)) { "Credential not yet valid" }
            check(expirationTime == null || !now.after(expirationTime)) { "Credential expired" }
            check(this.issuer == issuerId) { "Issuer mismatch" }
        }

        // Add Credential to WaltId storage
        //
        widWalletService.addCredential(ctx.walletId, format, sigJwt)

        return vcJwt
    }

}