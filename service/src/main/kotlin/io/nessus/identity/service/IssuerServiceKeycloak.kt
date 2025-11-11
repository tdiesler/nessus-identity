package io.nessus.identity.service

import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.PlainJWT
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
import jakarta.ws.rs.core.HttpHeaders
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
class IssuerServiceKeycloak(val issuerCfg: IssuerConfig) : AbstractIssuerService<IssuerMetadataV10>() {

    val issuerBaseUrl = issuerCfg.baseUrl
    val issuerUrl = "$issuerBaseUrl/realms/${issuerCfg.realm}"

    /**
     * Creates a CredentialOffer for the given credential configuration id
     */
    suspend fun createCredentialOfferThroughKeycloak(
        credConfigId: String,
    ): CredentialOfferV10 {

        val metadata = getIssuerMetadata()
        val supportedTypes = metadata.supportedTypes

        require(credConfigId in supportedTypes) { "UnsupportedType: $credConfigId" }

        val cfg = requireIssuerConfig()
        val issMetadata = getIssuerMetadata()

        val tokReq = TokenRequest.ClientCredentials(
            clientId = cfg.serviceId,
            clientSecret = cfg.serviceSecret,
            scopes = listOf(credConfigId),
        )

        val tokenEndpointUri = issMetadata.getAuthorizationTokenEndpoint()
        val tokRes = OAuthClient().sendTokenRequest(tokenEndpointUri, tokReq)

        val credentialOfferUrl = "$issuerUrl/credential-offer-uri"
        val apiRes = http.get(credentialOfferUrl) {
            header(HttpHeaders.AUTHORIZATION, "Bearer ${tokRes.accessToken}")
            url {
                parameter("credential_configuration_id", credConfigId)
            }
        }
        val credOffer = handleApiResponse(apiRes) as CredentialOfferV10

        log.info { "Issued CredentialOffer: ${credOffer.toJson()}" }
        return credOffer
    }

    /**
     * Creates a CredentialOffer for the given subject and credential types
     */
    suspend fun createCredentialOffer(
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
                val preAuthCode = issuerState
                Grants(preAuthorizedCode = PreAuthorizedCodeGrant(preAuthorizedCode = preAuthCode))
            } else {
                val clientId = issuerCfg.clientId
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

    fun getUsers(): List<UserRepresentation> {
        val realm = issuerCfg.realm
        keycloakConnect(realm).use {
            val usersResource = it.realm(realm).users()
            val realmUsers = usersResource.list()
            return realmUsers
        }
    }

    fun createUser(firstName: String, lastName: String, email: String, username: String, password: String): UserRepresentation {
        val realm = issuerCfg.realm
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
        val realm = issuerCfg.realm
        keycloakConnect(realm).use {
            it.realm(realm).users().delete(userId)
        }
    }

    override fun getIssuerMetadataUrl(): String {
        val metadataUrl = "$issuerBaseUrl/.well-known/openid-credential-issuer/realms/${issuerCfg.realm}"
        return metadataUrl
    }

    override suspend fun getIssuerMetadata(): IssuerMetadataV10 {
        val metadataUrl = URI(getIssuerMetadataUrl()).toURL()
        log.info { "IssuerMetadataUrl: $metadataUrl" }
        return http.get(metadataUrl).body<IssuerMetadataV10>()
    }

    // Private ---------------------------------------------------------------------------------------------------------

    private fun keycloakConnect(realm: String): Keycloak {
        val kc = KeycloakBuilder.builder()
            .serverUrl(issuerBaseUrl)
            .clientId(issuerCfg.serviceId)
            .clientSecret(issuerCfg.serviceSecret)
            .grantType(OAuth2Constants.CLIENT_CREDENTIALS)
            .realm(realm)
            .build()
        log.info { "Connected to Keycloak realm: $realm" }
        return kc
    }

}