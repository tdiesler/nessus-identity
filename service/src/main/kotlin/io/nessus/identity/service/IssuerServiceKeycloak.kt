package io.nessus.identity.service

import com.nimbusds.jwt.SignedJWT
import io.ktor.client.call.*
import io.ktor.client.request.*
import io.ktor.client.statement.*
import io.nessus.identity.config.ConfigProvider.requireIssuerConfig
import io.nessus.identity.config.IssuerConfig
import io.nessus.identity.service.OAuthClient.Companion.handleApiResponse
import io.nessus.identity.types.CredentialOfferUri
import io.nessus.identity.types.IssuerMetadataV0
import io.nessus.identity.types.OfferUriType
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

// KeycloakIssuerService =======================================================================================================================================

/**
 * Keycloak as OID4VC Issuer
 *
 * https://www.keycloak.org/docs/latest/server_admin/index.html#_oid4vci
 */
class IssuerServiceKeycloak(val config: IssuerConfig) : AbstractIssuerService<IssuerMetadataV0>() {

    val issuerBaseUrl = config.baseUrl
    val issuerUrl = "$issuerBaseUrl/realms/${config.realm}"

    override fun getIssuerMetadataUrl(): String {
        val metadataUrl = "$issuerBaseUrl/.well-known/openid-credential-issuer/realms/${config.realm}"
        return metadataUrl
    }

    override suspend fun getIssuerMetadata(): IssuerMetadataV0 {
        val metadataUrl = URI(getIssuerMetadataUrl()).toURL()
        log.info { "IssuerMetadataUrl: $metadataUrl" }
        return http.get(metadataUrl).body<IssuerMetadataV0>()
    }

    /**
     * Creates a CredentialOfferUri for the given credential configuration id
     */
    suspend fun createCredentialOfferUri(
        issuer: User,
        credConfigId: String,
        preAuthorized: Boolean = false,
        holder: User? = null,
    ): String {

        val credOfferUriRes = createCredentialOfferUriInternal(issuer, credConfigId, preAuthorized, holder,
            OfferUriType.URI)

        val credOfferUriJson = handleApiResponse(credOfferUriRes) as JsonObject
        val issuerUrl = credOfferUriJson.getValue("issuer").jsonPrimitive.content
        val nonce = credOfferUriJson.getValue("nonce").jsonPrimitive.content

        val credOfferUri = "$issuerUrl$nonce"
        log.info { "CredentialOfferUri: $credOfferUri" }

        return credOfferUri
    }

    /**
     * Creates a CredentialOfferUri QR Code
     */
    suspend fun createCredentialOfferUriQRCode(
        issuer: User,
        credConfigId: String,
        preAuthorized: Boolean = false,
        holder: User? = null,
    ): ByteArray {

        val credOfferUriRes = createCredentialOfferUriInternal(issuer, credConfigId, preAuthorized, holder,
            OfferUriType.QR_CODE)

        return handleApiResponse(credOfferUriRes) as ByteArray
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

    fun createUser(
        firstName: String,
        lastName: String,
        email: String,
        username: String,
        password: String
    ): UserRepresentation {
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

    private suspend fun createCredentialOfferUriInternal(
        issuer: User,
        credConfigId: String,
        preAuthorized: Boolean,
        holder: User?,
        type: OfferUriType?,
    ): HttpResponse {

        val issuerMetadata = getIssuerMetadata()
        val scope = requireNotNull(issuerMetadata.getCredentialScope(credConfigId))
        { "No credential scope for: $credConfigId" }

        val cfg = requireIssuerConfig()

        val tokReq = TokenRequest.DirectAccess(
            clientId = cfg.clientId,
            username = issuer.username,
            password = issuer.password,
            scopes = listOf(scope)
        )

        val tokenEndpointUri = issuerMetadata.getAuthorizationTokenEndpointUri()
        val tokRes = OAuthClient().sendTokenRequest(tokenEndpointUri, tokReq)
        val accessToken = tokRes.accessToken

        val tokenJwt = SignedJWT.parse(accessToken)
        log.info { "AccessToken: ${tokenJwt.jwtClaimsSet}" }

        val params = CredentialOfferUri(issuer, credConfigId)
            .withPreAuthorized(preAuthorized)
        holder?.also { params.withUserId(it.username) }
        type?.also { params.withType(it) }

        val credOfferUriUrl = "$issuerUrl/protocol/oid4vc/credential-offer-uri"
        log.info { "CredentialOfferUriReq: $credOfferUriUrl?${params.getUrlQuery()}" }
        val credOfferUriRes = http.get(credOfferUriUrl) {
            header(HttpHeaders.AUTHORIZATION, "Bearer $accessToken")
            url {
                params.parameters().forEach { (k, v) ->
                    parameter(k, v)
                }
            }
        }
        return credOfferUriRes
    }

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