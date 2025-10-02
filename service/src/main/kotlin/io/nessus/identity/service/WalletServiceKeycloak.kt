package io.nessus.identity.service

import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.util.Base64URL
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import id.walt.oid4vc.requests.AuthorizationRequest
import id.walt.oid4vc.requests.TokenRequest
import id.walt.oid4vc.responses.TokenResponse
import io.ktor.client.request.*
import io.ktor.client.statement.*
import io.ktor.http.*
import io.nessus.identity.extend.getQueryParameters
import io.nessus.identity.extend.signWithKey
import io.nessus.identity.types.AuthorizationRequestBuilder
import io.nessus.identity.types.CredentialOfferDraft17
import io.nessus.identity.types.IssuerMetadataDraft17
import io.nessus.identity.waltid.WaltIDServiceProvider.widWalletSvc
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import java.net.URI
import java.time.Instant
import java.util.*
import kotlin.random.Random

// WalletServiceKeycloak =======================================================================================================================================

class WalletServiceKeycloak : AbstractWalletService<CredentialOfferDraft17>() {

    // [TODO #282] Derive Keycloak clientId from CredentialOffer
    // https://github.com/tdiesler/nessus-identity/issues/282
    val clientId = "oid4vci-client"

    private val credRegistry = mutableMapOf<String, JsonObject>()

    /**
     * Holder builds the AuthorizationRequest from a CredentialOffer
     */
    suspend fun authorizationContextFromOffer(
        ctx: OIDContext,
        redirectUri: String,
        credOffer: CredentialOfferDraft17,
    ): AuthorizationContext {

        // Resolve the Issuer's metadata from the CredentialOffer
        val metadata = resolveIssuerMetadata(ctx, credOffer) as IssuerMetadataDraft17

        val rndBytes = Random.nextBytes(32)
        val codeVerifier = Base64URL.encode(rndBytes).toString()

        val authReq = buildAuthorizationRequest(redirectUri, credOffer, codeVerifier)

        val authContext = AuthorizationContext(ctx).
            withIssuerMetadata(metadata).
            withCredentialOffer(credOffer).
            withCodeVerifier(codeVerifier).
            withAuthorizationRequest(authReq)

        return authContext
    }

    /**
     * Holder gets a Credential from an Issuer based on a CredentialOffer
     * https://hub.ebsi.eu/conformance/build-solutions/issue-to-holder-functional-flows#in-time-issuance
     */
    suspend fun credentialFromOfferInTime(authContext: AuthorizationContext): JsonObject {

        val credOffer = authContext.credOffer ?: error("No Credential Offer")

        // Holder sends a TokenRequest to obtain an AccessToken
        // https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-token-request
        val tokenRes = sendTokenRequest(authContext)
        log.info { "AccessToken: ${tokenRes.accessToken}" }

        // Holder sends a CredentialRequest
        //
        val credRes = sendCredentialRequest(OIDContext(authContext), credOffer, tokenRes)
        log.info { "CredentialResponse: $credRes" }

        // Extract the VerifiableCredential from the CredentialResponse
        val credJwt = credRes.getValue("credentials").jsonArray
            .map { it.jsonObject }
            .map { it.getValue("credential").jsonPrimitive.content }
            .map { SignedJWT.parse(it) }
            .first()

        log.info { "CredentialJwt Header: ${credJwt.header}" }
        log.info { "CredentialJwt Claims: ${credJwt.jwtClaimsSet}" }

        // [TODO #268] Keycloak credential cannot be decoded to W3CCredential
        // https://github.com/tdiesler/nessus-identity/issues/268
        val credObj = Json.decodeFromString<JsonObject>("${credJwt.payload}")
        log.info { "Credential: $credObj" }
        val jti = credObj.getValue("jti").jsonPrimitive.content
        credRegistry[jti] = credObj
        return credObj
    }

    fun getCredentials(
        ctx: LoginContext,
    ): Map<String, JsonObject> {
        return credRegistry.toMap()
    }

    fun getCredential(
        ctx: LoginContext,
        credId: String
    ): JsonObject? {
        return credRegistry[credId]
    }

    fun deleteCredential(
        ctx: LoginContext,
        credId: String
    ): JsonObject? {
        return credRegistry.remove(credId)
    }

    // Private -------------------------------------------------------------------------------------------------------------------------------------------------

    private suspend fun buildAuthorizationRequest(
        redirectUri: String,
        credOffer: CredentialOfferDraft17,
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

    /**
     * Send an AuthorizationRequest to Keycloak
     *
     * @return The requested auth code
     */
    private fun sendAuthorizationRequest(
        authEndpointUrl: String,
        authReq: AuthorizationRequest,
        authCallbackHandler: (URI, AuthorizationRequest) -> String
    ): String {
        val authRequestUrl = URI("$authEndpointUrl?${authReq.getQueryParameters()}")
        log.info { "AuthorizationRequest: $authRequestUrl" }
        return authCallbackHandler(authRequestUrl, authReq)
    }

    private suspend fun sendTokenRequest(authContext: AuthorizationContext): TokenResponse {

        val authCode = authContext.authCode ?: error("No Auth Code")
        val authReq = authContext.authRequest ?: error("No AuthorizationRequest")
        val codeVerifier = authContext.codeVerifier ?: error("No Code Verifier")
        val metadata = authContext.metadata ?: error("No IssuerMetadata")

        val tokenEndpointUrl = metadata.getAuthorizationTokenEndpoint()

        val tokenReq = TokenRequest.AuthorizationCode(
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
        if (res.status != HttpStatusCode.OK)
            throw HttpStatusException(res.status, res.bodyAsText())

        val tokenRes = TokenResponse.fromJSONString(res.bodyAsText())
        log.info { "TokenResponse: ${tokenRes.toJSONString()}" }
        return tokenRes
    }

    private suspend fun sendCredentialRequest(
        ctx: OIDContext,
        credOffer: CredentialOfferDraft17,
        tokenRes: TokenResponse
    ): JsonObject {

        val metadata: IssuerMetadataDraft17 = resolveIssuerMetadata(ctx, credOffer)

        val ctypes = credOffer.getTypes()
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
        val ecKeyJson = widWalletSvc.exportKey(ctx, kid)
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

        // [TODO #267] CredentialRequest + CredentialResponse type for Draft17
        // https://github.com/tdiesler/nessus-identity/issues/267
        val credReqObj = Json.decodeFromString<JsonObject>(
            """{
          "credential_configuration_id": "$ctype",
          "proofs": {
            "jwt": [ "${proofJwt.serialize()}" ]
            }
          }"""
        )

        //val credReq = Json.decodeFromString<CredentialRequest>(credReqJson)
        log.info { "CredentialRequest: $credReqObj" }

        val res = http.post(metadata.credentialEndpoint) {
            header(HttpHeaders.Authorization, "Bearer ${tokenRes.accessToken}")
            contentType(ContentType.Application.Json)
            setBody(credReqObj)
        }
        if (res.status != HttpStatusCode.OK)
            throw HttpStatusException(res.status, res.bodyAsText())

        val credRes = Json.decodeFromString<JsonObject>(res.bodyAsText())
        return credRes
    }
}