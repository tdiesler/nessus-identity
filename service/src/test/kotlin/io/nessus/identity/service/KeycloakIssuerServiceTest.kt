package io.nessus.identity.service

import com.microsoft.playwright.BrowserType
import com.microsoft.playwright.Playwright
import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import id.walt.oid4vc.requests.TokenRequest
import id.walt.oid4vc.responses.TokenResponse
import io.kotest.common.runBlocking
import io.kotest.matchers.equals.shouldBeEqual
import io.ktor.client.request.*
import io.ktor.client.statement.*
import io.ktor.http.*
import io.nessus.identity.extend.getQueryParameters
import io.nessus.identity.extend.signWithKey
import io.nessus.identity.types.AuthorizationRequestBuilder
import io.nessus.identity.types.CredentialOfferDraft17
import io.nessus.identity.types.IssuerMetadata
import io.nessus.identity.types.IssuerMetadataDraft17
import io.nessus.identity.waltid.Alice
import io.nessus.identity.waltid.Max
import io.nessus.identity.waltid.WaltIDServiceProvider.widWalletSvc
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import java.time.Instant
import java.util.*


class KeycloakIssuerServiceTest : AbstractIssuerServiceTest<CredentialOfferDraft17, IssuerMetadataDraft17>() {

    @BeforeEach
    fun setUp() {
        issuerSrv = IssuerService.createKeycloak()
    }

    @Test
    fun testGetCredentialOffer() {
        /*
            Credential Offer Endpoint
            https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-credential-offer-endpoint
        */
        runBlocking {

            // Issuer's OIDC context (Max is the Issuer)
            val max = OIDContext(setupWalletWithDid(Max))

            // Holders's OIDC context (Alice is the Holder)
            val alice = OIDContext(setupWalletWithDid(Alice))

            issuerSrv.createCredentialOffer(max, alice.did, listOf("oid4vc_identity_credential"))

            assertThrows<IllegalArgumentException> {
                issuerSrv.createCredentialOffer(max, alice.did, listOf("oid4vc_unknown"))
            }
        }
    }

    @Test
    fun issueCredentialInTime() {
        /*
            Authorization Code Flow
            https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-authorization-code-flow
        */
        runBlocking {

            // Issuer's OIDC context (Max is the Issuer)
            val max = OIDContext(setupWalletWithDid(Max))

            // Holders's OIDC context (Alice is the Holder)
            val alice = OIDContext(setupWalletWithDid(Alice))

            val clientId = "oid4vci-client"
            val ctype = "oid4vc_identity_credential"
            val redirectUri = "urn:ietf:wg:oauth:2.0:oob"

            // [TODO] Keycloak requires clientSecret in Token request
            // https://github.com/tdiesler/nessus-identity/issues/265
            val clientSecret = "gxHjJs0d1b2UvX1yy4eaw4lIZIopk3ds"

            // Get the IssuerMetadata and make it knows to the Holder
            val metadata = issuerSrv.getIssuerMetadata(max)
            alice.issuerMetadata = (metadata as IssuerMetadata)

            // Issuer generates a CredentialOffer and (somehow) passes it the Holder's wallet
            // https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-credential-offer-endpoint
            val credOffer = issuerSrv.createCredentialOffer(max, alice.did, listOf(ctype))

            // Holder builds an Authorization Request
            //
            val authReq = AuthorizationRequestBuilder()
                .withClientId(clientId)
                .withRedirectUri(redirectUri)
                .buildFrom(credOffer)

            // Holder sends an Authorization Request to obtain an Authorization Code
            // https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-authorization-request
            val authEndpointUrl = "${metadata.credentialIssuer}/protocol/openid-connect/auth"
            val authRequestUrl = "$authEndpointUrl?${authReq.getQueryParameters()}"
            log.info { "AuthorizationRequestUrl: $authRequestUrl" }

            val authCode = sendAuthorizationRequest(authRequestUrl, Alice.username, Alice.password)
            log.info { "AuthCode: $authCode" }

            // Holder sends a TokenRequest to obtain an AccessToken
            // https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-token-request
            val tokenEndpointUrl = "${metadata.credentialIssuer}/protocol/openid-connect/token"
            val tokenRequest = TokenRequest.AuthorizationCode(
                clientId = clientId,
                redirectUri = redirectUri,
                code = authCode,
                customParameters = mapOf("clientSecret" to listOf(clientSecret))
            )
            val tokenRes = sendTokenRequest(tokenEndpointUrl, tokenRequest)
            log.info { "TokenResponse: ${tokenRes.toJSONString()}" }
            log.info { "AccessToken: ${tokenRes.accessToken}" }

            // Holder sends a CredentialRequest
            //
            val offerTypes = credOffer.getTypes()
            val credRes = sendCredentialRequest(alice, offerTypes, tokenRes)
            log.info { "CredentialResponse: $credRes" }

            val credJwt = credRes.getValue("credentials").jsonArray
                .map { it.jsonObject }
                .map { it.getValue("credential").jsonPrimitive.content }
                .map { SignedJWT.parse(it) }
                .first()

            log.info { "CredentialJwt Header: ${credJwt.header}" }
            log.info { "CredentialJwt Claims: ${credJwt.jwtClaimsSet}" }

            // [TODO] Keycloak credential cannot be decoded to W3CCredential
            // https://github.com/tdiesler/nessus-identity/issues/268
            val credObj = Json.decodeFromString<JsonObject>("${credJwt.payload}")
            val vc = credObj.getValue("vc").jsonObject
            log.info { "Credential: $vc" }

            val wasTypes = vc.getValue("type").jsonArray.map { it.jsonPrimitive.content }
            offerTypes shouldBeEqual wasTypes

            val subject = vc.getValue("credentialSubject").jsonObject
            subject.getValue("email").jsonPrimitive.content shouldBeEqual Alice.email
            subject.getValue("id").jsonPrimitive.content shouldBeEqual alice.did
        }
    }

    /**
     * Send an AuthorizationRequest to Keycloak
     * Authenticates with username/password on the 'urn:ietf:wg:oauth:2.0:oob' page
     * @return The requested auth code
     */
    fun sendAuthorizationRequest(reqUrl: String, username: String, password: String): String {
        Playwright.create().use { plw ->
            val browser = plw.webkit().launch(
                BrowserType.LaunchOptions().setHeadless(true)
            )
            val page = browser.newPage()

            // Navigate to Keycloak Authorization Endpoint
            page.navigate(reqUrl)

            // Fill in login form (adjust selectors if your Keycloak theme differs)
            page.locator("#username").fill(username)
            page.locator("#password").fill(password)
            page.locator("#kc-login").click()

            // Wait for the input with id="code"
            page.waitForSelector("#code")

            // Extract the code from the 'value' attribute
            val authCode = page.locator("#code").getAttribute("value")

            browser.close()
            return authCode
        }
    }

    /**
     * Send a TokenRequest
     *
     */
    suspend fun sendTokenRequest(tokenEndpointUrl: String, tokenReq: TokenRequest.AuthorizationCode): TokenResponse {
        val clientSecret = tokenReq.customParameters["clientSecret"]?.first() ?: throw IllegalStateException("No clientSecret")
        val res = http.post(tokenEndpointUrl) {
            contentType(ContentType.Application.FormUrlEncoded)
            setBody(
                Parameters.build {
                    append("grant_type", "authorization_code")
                    append("client_id", tokenReq.clientId)
                    append("client_secret", clientSecret)
                    append("code", tokenReq.code)
                    append("redirect_uri", tokenReq.redirectUri!!)
                    // append("code_verifier", codeVerifier) // when using PKCE
                }.formUrlEncode()
            )
        }
        if (res.status != HttpStatusCode.OK)
            throw HttpStatusException(res.status, res.bodyAsText())

        val tokRes = TokenResponse.fromJSONString(res.bodyAsText())
        return tokRes
    }

    suspend fun sendCredentialRequest(ctx: OIDContext, types: List<String>, tokenRes: TokenResponse): JsonObject {

        if (types.size != 1) throw IllegalArgumentException("Multiple types not supported: $types")
        val ctype = types.first()

        val metadata = ctx.issuerMetadata as IssuerMetadataDraft17

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
        log.info { "Public ECKeyB: $publicJwk" }

        val iat = Instant.now()
        val exp = iat.plusSeconds(300) // 5 mins expiry

        val claims = JWTClaimsSet.Builder()
            .audience(metadata.credentialIssuer)
            .issueTime(Date.from(iat))
            .expirationTime(Date.from(exp))
            .claim("nonce", cNonce)
            .build()

        val header = JWSHeader.Builder(JWSAlgorithm.ES256)
            .type(JOSEObjectType("openid4vci-proof+jwt"))
            .jwk(publicJwk) // embed JWK directly
            .build()

        val proofJwt = SignedJWT(header, claims).signWithKey(ctx, kid)
        log.info { "ProofJwt Header: ${proofJwt.header}" }
        log.info { "ProofJwt Claims: ${proofJwt.jwtClaimsSet}" }

        // [TODO] Creating a CredentialRequest type for Draft17
        // https://github.com/tdiesler/nessus-identity/issues/266
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