package io.nessus.identity.service

import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.PlainJWT
import com.nimbusds.jwt.SignedJWT
import io.ktor.client.call.*
import io.ktor.client.request.*
import io.nessus.identity.config.ConfigProvider.requireIssuerConfig
import io.nessus.identity.config.IssuerConfig
import io.nessus.identity.service.CredentialOfferRegistry.putCredentialOfferRecord
import io.nessus.identity.service.OAuthClient.Companion.handleApiResponse
import io.nessus.identity.types.AuthorizationCodeGrant
import io.nessus.identity.types.CredentialOfferV10
import io.nessus.identity.types.Grants
import io.nessus.identity.types.IssuerMetadataV10
import io.nessus.identity.types.PreAuthorizedCodeGrant
import io.nessus.identity.types.TokenRequest
import io.nessus.identity.waltid.User
import jakarta.ws.rs.core.HttpHeaders
import kotlinx.serialization.json.*
import org.keycloak.OAuth2Constants
import org.keycloak.admin.client.Keycloak
import org.keycloak.admin.client.KeycloakBuilder
import org.keycloak.representations.idm.CredentialRepresentation
import org.keycloak.representations.idm.UserRepresentation
import java.net.URI
import java.util.*
import kotlin.time.Clock
import kotlin.time.Duration.Companion.minutes

// KeycloakIssuerService =======================================================================================================================================

/**
 * Keycloak as OID4VC Issuer
 *
 * https://www.keycloak.org/docs/latest/server_admin/index.html#_oid4vci
 */
class IssuerServiceKeycloak(val config: IssuerConfig) : AbstractIssuerService<IssuerMetadataV10>() {

    val issuerBaseUrl = config.baseUrl
    val issuerUrl = "$issuerBaseUrl/realms/${config.realm}"

    override fun getIssuerMetadataUrl(): String {
        val metadataUrl = "$issuerBaseUrl/.well-known/openid-credential-issuer/realms/${config.realm}"
        return metadataUrl
    }

    override suspend fun getIssuerMetadata(): IssuerMetadataV10 {
        val metadataUrl = URI(getIssuerMetadataUrl()).toURL()
        log.info { "IssuerMetadataUrl: $metadataUrl" }
        return http.get(metadataUrl).body<IssuerMetadataV10>()
    }

    /**
     * Creates a CredentialOfferUri for the given credential configuration id
     */
    suspend fun createCredentialOfferUri(issuer: User, ctype: String, preAuthorized: Boolean = false, holder: User? = null): String {

        val metadata = getIssuerMetadata()
        val supportedTypes = metadata.supportedTypes

        require(ctype in supportedTypes) { "UnsupportedType: $ctype" }

        val cfg = requireIssuerConfig()
        val issMetadata = getIssuerMetadata()

        val tokReq = TokenRequest.DirectAccess(
            clientId = cfg.clientId,
            username = issuer.username,
            password = issuer.password,
            scopes = listOf(ctype)
        )

        val tokenEndpointUri = issMetadata.getAuthorizationTokenEndpoint()
        val tokRes = OAuthClient().sendTokenRequest(tokenEndpointUri, tokReq)
        val accessToken = tokRes.accessToken

        val tokenJwt = SignedJWT.parse(accessToken)
        log.info { "AccessToken: ${tokenJwt.jwtClaimsSet}" }

        val credOfferUriUrl = "$issuerUrl/protocol/oid4vc/credential-offer-uri"
        log.info { "CredentialOfferUriReq: $credOfferUriUrl?credential_configuration_id=$ctype" }
        val credOfferUriRes = http.get(credOfferUriUrl) {
            header(HttpHeaders.AUTHORIZATION, "Bearer $accessToken")
            url {
                parameter("credential_configuration_id", ctype)
                parameter("pre_authorized", preAuthorized)
                if (preAuthorized) {
                    val email = holder?.email ?: error("No user email")
                    val user = findUserByEmail(email) ?: error("No user for email: $email")
                    parameter("user_id", user.username)
                }
            }
        }
        val credOfferUriJson = handleApiResponse(credOfferUriRes) as JsonObject
        val issuerUrl = credOfferUriJson.getValue("issuer").jsonPrimitive.content
        val nonce = credOfferUriJson.getValue("nonce").jsonPrimitive.content

        val credOfferUri = "$issuerUrl$nonce"
        log.info { "CredentialOfferUri: $credOfferUri}" }

        return credOfferUri
    }

    /**
     * Creates a CredentialOffer for the given subject and credential types
     */
    suspend fun createCredentialOfferNative(
        subjectId: String,
        types: List<String>,
        userPin: String? = null
    ): CredentialOfferV10 {

        val metadata = getIssuerMetadata()
        val issuerUri = metadata.credentialIssuer
        val supportedTypes = metadata.supportedTypes

        types.firstOrNull { it !in supportedTypes }?.let {
            throw IllegalArgumentException("UnsupportedType: $it")
        }

        // Build issuer state jwt
        val iat = Clock.System.now()
        val exp = iat + 5.minutes // 5min

        val issuerStateClaims = JWTClaimsSet.Builder()
            .subject(subjectId)
            .issuer(issuerUrl)
            .issueTime(Date(iat.toEpochMilliseconds()))
            .expirationTime(Date(exp.toEpochMilliseconds()))
            .claim("credential_types", types)
            .build()

        // Unsigned JWT
        val issuerStateJwt = PlainJWT(issuerStateClaims)
        val issuerState = issuerStateJwt.serialize()

        // Build CredentialOffer
        val credOffer = CredentialOfferV10(
            credentialIssuer = issuerUri,
            credentialConfigurationIds = types,
            grants = if (userPin != null) {
                Grants(preAuthorizedCode = PreAuthorizedCodeGrant(preAuthorizedCode = issuerState))
            } else {
                val clientId = config.clientId
                val issuerState = issuerState
                Grants(authorizationCode = AuthorizationCodeGrant(issuerState, clientId = clientId))
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

    fun findUserByEmail(email: String): UserRepresentation? {
        val realm = config.realm
        keycloakConnect(realm).use {
            val usersResource = it.realm(realm).users()
            val realmUsers = usersResource.searchByEmail(email, true)
            return realmUsers.firstOrNull()
        }
    }

    fun getUsers(): List<UserRepresentation> {
        val realm = config.realm
        keycloakConnect(realm).use {
            val usersResource = it.realm(realm).users()
            val realmUsers = usersResource.list()
            return realmUsers
        }
    }

    fun createUser(firstName: String, lastName: String, email: String, username: String, password: String): UserRepresentation {
        val realm = config.realm
        val user = UserRepresentation().apply {
            this.username = username
            this.email = email
            this.firstName = firstName
            this.lastName = lastName
            this.isEnabled = true
            this.isEmailVerified = true
        }

        keycloakConnect(realm).use { keycloak ->
            val users = keycloak.realm(realm).users()
            val res = users.create(user)
            if (res.status != 201) {
                error("Failed to create user: ${res.statusInfo.reasonPhrase}")
            }
            val userId = res.location.path.substringAfterLast('/')
            log.info { "Created user with ID: $userId" }

            val credential = CredentialRepresentation().apply {
                type = CredentialRepresentation.PASSWORD
                value = password
                isTemporary = false
            }

            val user = users.get(userId)
            user.resetPassword(credential)

            return user.toRepresentation()
        }
    }

    fun deleteUser(userId: String) {
        val realm = config.realm
        keycloakConnect(realm).use {
            it.realm(realm).users().delete(userId)
        }
    }

    // Private ---------------------------------------------------------------------------------------------------------

    private fun keycloakConnect(realm: String): Keycloak {
        val kc = KeycloakBuilder.builder()
            .serverUrl(issuerBaseUrl)
            .clientId(config.serviceId)
            .clientSecret(config.serviceSecret)
            .grantType(OAuth2Constants.CLIENT_CREDENTIALS)
            .realm(realm)
            .build()
        log.info { "Connected to Keycloak realm: $realm" }
        return kc
    }

}