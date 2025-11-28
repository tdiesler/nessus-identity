package io.nessus.identity.service

import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import id.walt.oid4vc.data.CredentialFormat
import id.walt.oid4vc.data.CredentialSupported
import id.walt.oid4vc.data.DisplayProperties
import id.walt.oid4vc.data.GrantType
import id.walt.oid4vc.data.OpenIDProviderMetadata
import id.walt.oid4vc.data.SubjectType
import io.nessus.identity.config.IssuerConfig
import io.nessus.identity.config.User
import io.nessus.identity.extend.signWithKey
import io.nessus.identity.service.AuthorizationContext.Companion.EBSI32_AUTHORIZATION_REQUEST_DRAFT11_ATTACHMENT_KEY
import io.nessus.identity.service.CredentialOfferRegistry.putCredentialOfferRecord
import io.nessus.identity.service.UserAccessService.UserInfo
import io.nessus.identity.types.AuthorizationCodeGrant
import io.nessus.identity.types.AuthorizationMetadata
import io.nessus.identity.types.AuthorizationRequest
import io.nessus.identity.types.AuthorizationRequestDraft11
import io.nessus.identity.types.CredentialObject
import io.nessus.identity.types.CredentialOffer
import io.nessus.identity.types.CredentialOfferDraft11
import io.nessus.identity.types.Grants
import io.nessus.identity.types.IssuerMetadataDraft11
import io.nessus.identity.types.PreAuthorizedCodeGrant
import io.nessus.identity.waltid.authenticationId
import kotlinx.coroutines.runBlocking
import java.time.Instant
import java.util.*

// IssuerServiceEbsi32 =================================================================================================

class IssuerServiceEbsi32(val config: IssuerConfig) : AbstractIssuerService(), IssuerService {

    private var adminContext: LoginContext

    override val authorizationSvc = AuthorizationService.create()

    init {
        runBlocking {
            adminContext = LoginContext.login(config.adminUser).withDidInfo()
        }
    }

    /**
     * Get the authorization metadata
     */
    override suspend fun getAuthorizationMetadata(): AuthorizationMetadata {
        val targetUri = "$endpointUri/${adminContext.targetId}"
        return authorizationSvc.buildAuthorizationMetadata(targetUri)
    }

    override suspend fun createCredentialOfferUri(
        configId: String,
        clientId: String?,
        preAuthorized: Boolean,
        userPin: String?,
        targetUser: User?,
    ): String {
        error("Not implemented")
    }

    override suspend fun createCredentialOffer(
        configId: String,
        clientId: String?,
        preAuthorized: Boolean,
        userPin: String?,
        targetUser: User?,
    ): CredentialOffer {

        val ctx = adminContext
        val issuerMetadata = getIssuerMetadata()
        val issuerUri = issuerMetadata.credentialIssuer

        val credConfig = issuerMetadata.credentialsSupported.first { it.types!!.contains(configId) }
        val ctypes = requireNotNull(credConfig.types) { "No types " }

        // Build issuer state jwt
        val iat = Instant.now()
        val exp = iat.plusSeconds(300) // 5min
        val aud = issuerMetadata.authorizationServer
        val kid = ctx.didInfo.authenticationId()

        val header = JWSHeader.Builder(JWSAlgorithm.ES256)
            .type(JOSEObjectType.JWT)
            .keyID(kid)
            .build()

        val offerClaims = JWTClaimsSet.Builder()
            .subject(clientId)
            .audience(aud)
            .issuer(ctx.did)
            .issueTime(Date.from(iat))
            .expirationTime(Date.from(exp))
            .claim("client_id", clientId)
            .claim("credential_types", ctypes)
            .build()

        val credOfferJwt = SignedJWT(header, offerClaims).signWithKey(ctx, kid)

        // Build CredentialOffer
        val credOffer = CredentialOfferDraft11(
            credentialIssuer = issuerUri,
            credentials = listOf(CredentialObject(types = ctypes, format = credConfig.format)),
            grants = if (preAuthorized) {
                val preAuthCode = credOfferJwt.serialize()
                Grants(preAuthorizedCode = PreAuthorizedCodeGrant(preAuthorizedCode = preAuthCode))
            } else {
                val issuerState = credOfferJwt.serialize()
                Grants(authorizationCode = AuthorizationCodeGrant(issuerState = issuerState))
            }
        )

        // Record the CredentialOffer with UserPin
        //
        val preAuthCodeGrant = credOffer.getPreAuthorizedCodeGrant()
        if (preAuthCodeGrant != null) {
            val authCode = preAuthCodeGrant.preAuthorizedCode
            putCredentialOfferRecord(authCode, credOffer, userPin)
        }

        log.info { "Issued CredentialOffer: ${credOffer.toJson()}" }
        return credOffer
    }

    override suspend fun createIDTokenRequest(ctx: LoginContext, authRequest: AuthorizationRequest): AuthorizationRequest {

        val authContext = ctx.getAuthContext()
        authRequest as AuthorizationRequestDraft11
        authContext.putAttachment(EBSI32_AUTHORIZATION_REQUEST_DRAFT11_ATTACHMENT_KEY, authRequest)

        val targetEndpointUri = "${endpointUri}/${adminContext.targetId}"
        val redirectUri = requireNotNull(authRequest.redirectUri) { "No redirect_uri" }
        val idTokenRequestJwt = authorizationSvc.createIDTokenRequestJwt(ctx, targetEndpointUri, authRequest)
        val authRequestOut = authorizationSvc.buildIDTokenAuthorizationRequest(redirectUri, idTokenRequestJwt)

        return authRequestOut
    }

    override fun getAuthCodeFromIDToken(
        ctx: LoginContext,
        idTokenJwt: SignedJWT,
    ): String {
        val redirectUrl = authorizationSvc.getIDTokenRedirectUrl(ctx, idTokenJwt)
        val authCode = getAuthCodeFromRedirectUrl(redirectUrl)
        return authCode
    }

    override fun getIssuerMetadataUrl(): String {
        return "$endpointUri/${adminContext.targetId}/.well-known/openid-credential-issuer"
    }

    override suspend fun getIssuerMetadata(): IssuerMetadataDraft11 {
        val issuerMetadata = buildIssuerMetadata(adminContext)
        
        return issuerMetadata
    }

    override fun createUser(
        firstName: String,
        lastName: String,
        email: String,
        username: String,
        password: String
    ): UserInfo {
        error("Not implemented")
    }

    override fun findUser(predicate: (UserInfo) -> Boolean): UserInfo? {
        error("Not implemented")
    }

    override fun findUserByEmail(email: String): UserInfo? {
        error("Not implemented")
    }

    override fun getUsers(): List<UserInfo> {
        error("Not implemented")
    }

    override fun deleteUser(userId: String) {
        error("Not implemented")
    }

    // Private ---------------------------------------------------------------------------------------------------------

    private fun buildIssuerMetadata(ctx: LoginContext): IssuerMetadataDraft11 {
        val issuerTargetUrl = "$endpointUri/${ctx.targetId}"
        val credentialSupported = mapOf(
            "CTWalletSameAuthorisedInTime" to CredentialSupported(
                format = CredentialFormat.jwt_vc,
                display = listOf(DisplayProperties(locale = "en-GB", name = "CTWalletSameAuthorisedInTime")),
                types = listOf("VerifiableCredential", "VerifiableAttestation", "CTWalletSameAuthorisedInTime")
            ),
            "CTWalletSameAuthorisedDeferred" to CredentialSupported(
                format = CredentialFormat.jwt_vc,
                display = listOf(DisplayProperties(locale = "en-GB", name = "CTWalletSameAuthorisedDeferred")),
                types = listOf("VerifiableCredential", "VerifiableAttestation", "CTWalletSameAuthorisedDeferred")
            ),
            "CTWalletSamePreAuthorisedInTime" to CredentialSupported(
                format = CredentialFormat.jwt_vc,
                display = listOf(DisplayProperties(locale = "en-GB", name = "CTWalletSamePreAuthorisedInTime")),
                types = listOf("VerifiableCredential", "VerifiableAttestation", "CTWalletSamePreAuthorisedInTime")
            ),
            "CTWalletSamePreAuthorisedDeferred" to CredentialSupported(
                format = CredentialFormat.jwt_vc,
                display = listOf(DisplayProperties(locale = "en-GB", name = "CTWalletSamePreAuthorisedDeferred")),
                types = listOf("VerifiableCredential", "VerifiableAttestation", "CTWalletSamePreAuthorisedDeferred")
            ),
        )
        val waltDraft11 = OpenIDProviderMetadata.Draft11.create(
            issuer = issuerTargetUrl,
            authorizationServer = issuerTargetUrl,
            authorizationEndpoint = "$issuerTargetUrl/authorize",
            pushedAuthorizationRequestEndpoint = "$issuerTargetUrl/par",
            tokenEndpoint = "$issuerTargetUrl/token",
            credentialEndpoint = "$issuerTargetUrl/credential",
            batchCredentialEndpoint = "$issuerTargetUrl/batch_credential",
            deferredCredentialEndpoint = "$issuerTargetUrl/credential_deferred",
            jwksUri = "$issuerTargetUrl/jwks",
            grantTypesSupported = setOf(GrantType.authorization_code, GrantType.pre_authorized_code),
            requestUriParameterSupported = true,
            subjectTypesSupported = setOf(SubjectType.public),
            credentialIssuer = issuerTargetUrl,
            responseTypesSupported = setOf(
                "code",
                "vp_token",
                "id_token"
            ),
            idTokenSigningAlgValuesSupported = setOf("ES256"),
            codeChallengeMethodsSupported = listOf("S256"),
            credentialSupported = credentialSupported,
        )
        val metadata = IssuerMetadataDraft11.fromJson(waltDraft11.toJSONString())
        return metadata
    }
}