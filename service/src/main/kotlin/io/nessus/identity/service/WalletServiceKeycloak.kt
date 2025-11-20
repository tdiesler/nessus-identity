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
import io.nessus.identity.config.ConfigProvider.requireIssuerConfig
import io.nessus.identity.extend.signWithKey
import io.nessus.identity.service.LoginContext.Companion.AUTH_CONTEXT_ATTACHMENT_KEY
import io.nessus.identity.service.LoginContext.Companion.USER_ATTACHMENT_KEY
import io.nessus.identity.service.OAuthClient.Companion.handleApiResponse
import io.nessus.identity.types.AuthorizationRequest
import io.nessus.identity.types.AuthorizationRequestBuilder
import io.nessus.identity.types.CredentialOfferV0
import io.nessus.identity.types.CredentialRequestV0
import io.nessus.identity.types.CredentialResponseV0
import io.nessus.identity.types.IssuerMetadataV0
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

class WalletServiceKeycloak : AbstractWalletService<CredentialOfferV0>() {

    val clientId = requireIssuerConfig().clientId

    fun createAuthorizationContext(ctx: LoginContext? = null): AuthorizationContext {
        val authContext = AuthorizationContext(ctx)
        ctx?.also { it.putAttachment(AUTH_CONTEXT_ATTACHMENT_KEY, authContext) }
        return authContext
    }

    suspend fun buildAuthorizationRequest(
        authContext: AuthorizationContext,
        redirectUri: String = "urn:ietf:wg:oauth:2.0:oob"
    ): AuthorizationRequest {

        val rndBytes = Random.nextBytes(32)
        val codeVerifier = Base64URL.encode(rndBytes).toString()
        authContext.withCodeVerifier(codeVerifier)

        val issuerMetadata = authContext.getIssuerMetadata()

        val authRequest = if (authContext.credOffer != null) {
            val credOffer = authContext.credOffer ?: error("No credential offer")
            buildAuthorizationRequestFromOffer(redirectUri, credOffer, codeVerifier)
        } else {
            val configIds = authContext.credentialConfigurationIds ?: error("No credential configuration ids")
            buildAuthorizationRequestFromCredentialConfigurationIds(redirectUri, issuerMetadata, configIds, codeVerifier)
        }
        authContext.withAuthorizationRequest(authRequest)
        return authRequest
    }

    suspend fun getAuthorizationCode(
        authContext: AuthorizationContext,
        username: String,
        password: String,
        redirectUri: String = "urn:ietf:wg:oauth:2.0:oob"
    ): String {

        val issuerMetadata = authContext.getIssuerMetadata()
        val authRequest = buildAuthorizationRequest(authContext, redirectUri)
        val authEndpointUrl = issuerMetadata.getAuthorizationEndpoint()

        val authCode = OAuthClient()
            .withLoginCredentials(username, password)
            .sendAuthorizationRequest(authEndpointUrl, authRequest)

        return authCode
    }

    suspend fun getAccessTokenFromAuthorizationCode(authContext: AuthorizationContext, authCode: String): TokenResponseV0 {

        val authReq = authContext.authRequest
        val issuerMetadata = authContext.getIssuerMetadata()
        val codeVerifier = authContext.codeVerifier ?: error("No Code Verifier")

        val tokenEndpointUrl = issuerMetadata.getAuthorizationTokenEndpoint()

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

    suspend fun getAccessTokenFromDirectAccess(authContext: AuthorizationContext): TokenResponseV0 {

        val issuerMetadata = authContext.getIssuerMetadata()
        val tokenEndpointUrl = issuerMetadata.getAuthorizationTokenEndpoint()
        val scopes = mutableListOf("openid")

        authContext.credentialConfigurationIds?.also {
            scopes.addAll(it)
        }

        val loginContext = requireNotNull(authContext.loginContext) { "No login context "}
        val user = requireNotNull(loginContext.getAttachment(USER_ATTACHMENT_KEY)) { "No attached user "}

        val tokReq = TokenRequest.DirectAccess(
            clientId = clientId,
            username = user.username,
            password = user.password,
            scopes = scopes
        )

        val tokRes = OAuthClient().sendTokenRequest(tokenEndpointUrl, tokReq)
        log.info { "TokenResponse: ${tokRes.toJson()}" }
        return tokRes
    }

    suspend fun getAccessTokenFromPreAuthorizedCode(authContext: AuthorizationContext, credOffer: CredentialOfferV0): TokenResponseV0 {

        authContext.withCredentialOffer(credOffer)

        val issuerMetadata = authContext.getIssuerMetadata()
        val code = credOffer.getPreAuthorizedCodeGrant()?.preAuthorizedCode ?: error("No pre-authorized code")
        val tokenEndpointUrl = issuerMetadata.getAuthorizationTokenEndpoint()

        val tokReq = TokenRequest.PreAuthorizedCode(
            clientId = clientId,
            preAuthorizedCode = code,
        )

        val tokRes = OAuthClient().sendTokenRequest(tokenEndpointUrl, tokReq)
        log.info { "TokenResponse: ${tokRes.toJson()}" }
        return tokRes
    }

    /**
     * Fetch the CredentialOffer for the given credential offer uri
     */
    suspend fun fetchCredentialOffer(offerUri: String): CredentialOfferV0 {
        val credOfferRes = http.get(offerUri)
        val credOffer = (handleApiResponse(credOfferRes) as CredentialOfferV0)
        log.info { "CredentialOffer: ${credOffer.toJson()}" }
        return credOffer
    }

    /**
     * Holder gets a Credential from an Issuer based on a CredentialOffer
     * https://hub.ebsi.eu/conformance/build-solutions/issue-to-holder-functional-flows#in-time-issuance
     */
    suspend fun getCredential(authContext: AuthorizationContext, accessToken: TokenResponseV0): VCDataJwt {

        val credConfigIds = authContext.credentialConfigurationIds ?: error("No credential configuration ids")
        val credRes = sendCredentialRequest(authContext, credConfigIds, accessToken)

        val vcJwt = validateAndStoreCredential(authContext, credRes)
        return vcJwt
    }

    // Private -------------------------------------------------------------------------------------------------------------------------------------------------

    private suspend fun buildAuthorizationRequestFromCredentialConfigurationIds(
        redirectUri: String,
        metadata: IssuerMetadataV0,
        configIds: List<String>,
        codeVerifier: String? = null
    ): AuthorizationRequest {

        val scopes = metadata.credentialConfigurationsSupported
            .filter { (k, _) -> configIds.contains(k) }
            .mapNotNull { (_, v) -> v.scope }
            .toList()

        val builder = AuthorizationRequestBuilder()
            .withRedirectUri(redirectUri)
            .withIssuerMetadata(metadata)
            .withClientId(clientId)
            .withScopes(scopes)

        if (codeVerifier != null) {
            builder.withCodeChallengeMethod("S256")
            builder.withCodeVerifier(codeVerifier)
        }

        val authReq = builder.build()
        return authReq
    }

    private suspend fun buildAuthorizationRequestFromOffer(
        redirectUri: String,
        credOffer: CredentialOfferV0,
        codeVerifier: String? = null
    ): AuthorizationRequest {

        val builder = AuthorizationRequestBuilder()
            .withCredentialOffer(credOffer)
            .withRedirectUri(redirectUri)
            .withClientId(clientId)

        if (codeVerifier != null) {
            builder.withCodeChallengeMethod("S256")
            builder.withCodeVerifier(codeVerifier)
        }

        val authReq = builder.build()
        return authReq
    }

    private suspend fun sendCredentialRequest(
        authContext: AuthorizationContext,
        credConfigIds: List<String>,
        accessToken: TokenResponseV0
    ): CredentialResponseV0 {
        require(credConfigIds.size == 1) { "Expected single credential configuration id: $credConfigIds" }

        val issuerMetadata = authContext.getIssuerMetadata()
        val ctype = credConfigIds.first()

        val cNonce = accessToken.cNonce ?: let {
            val res = http.post(issuerMetadata.nonceEndpoint!!)
            if (res.status != HttpStatusCode.OK)
                throw HttpStatusException(res.status, res.bodyAsText())
            val jsonObj = Json.decodeFromString<JsonObject>(res.bodyAsText())
            jsonObj.getValue("c_nonce").jsonPrimitive.content
        }

        val loginContext = requireNotNull(authContext.loginContext) { "No login context "}
        val kid = loginContext.didInfo.keyId

        val ecKeyJson = widWalletService.exportKey(loginContext, kid)
        val publicJwk = JWK.parse(ecKeyJson) as ECKey
        log.info { "PublicJwk: $publicJwk" }

        val proofHeader = JWSHeader.Builder(JWSAlgorithm.ES256)
            .type(JOSEObjectType("openid4vci-proof+jwt"))
            .jwk(publicJwk) // embed JWK directly
            .build()

        val iat = Instant.now()
        val exp = iat.plusSeconds(300) // 5 mins expiry
        val proofClaims = JWTClaimsSet.Builder()
            .audience(issuerMetadata.credentialIssuer)
            .issueTime(Date.from(iat))
            .expirationTime(Date.from(exp))
            .claim("nonce", cNonce)
            .build()

        val proofJwt = SignedJWT(proofHeader, proofClaims).signWithKey(loginContext, kid)
        log.info { "ProofHeader: ${proofJwt.header}" }
        log.info { "ProofClaims: ${proofJwt.jwtClaimsSet}" }

        val credReq = CredentialRequestV0(
            credentialConfigurationId = ctype,
            proofs = CredentialRequestV0.Proofs(jwt = listOf(proofJwt.serialize()))
        )

        log.info { "CredentialRequest: ${Json.encodeToString(credReq)}" }

        val res = http.post(issuerMetadata.credentialEndpoint) {
            header(HttpHeaders.Authorization, "Bearer ${accessToken.accessToken}")
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
        authContext: AuthorizationContext,
        credRes: CredentialResponseV0
    ): VCDataJwt {

        val issuerMetadata = authContext.getIssuerMetadata()

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

        val credConfig = issuerMetadata.credentialConfigurationsSupported[ctype] ?: error("No credential_configurations_supported for: $ctype")
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
        authContext.loginContext?.also {
            widWalletService.addCredential(it.walletId, format, sigJwt)
        }

        return vcJwt
    }

}