package io.nessus.identity.service

import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.PlainJWT
import io.ktor.client.call.*
import io.ktor.client.request.*
import io.nessus.identity.config.IssuerConfig
import io.nessus.identity.service.CredentialOfferRegistry.putCredentialOfferRecord
import io.nessus.identity.types.AuthorizationCodeGrant
import io.nessus.identity.types.CredentialOfferV10
import io.nessus.identity.types.Grants
import io.nessus.identity.types.IssuerMetadataV10
import io.nessus.identity.types.PreAuthorizedCodeGrant
import org.keycloak.admin.client.KeycloakBuilder
import org.keycloak.representations.idm.UserRepresentation
import java.net.URI
import java.util.Date
import kotlin.time.Clock
import kotlin.time.Duration.Companion.minutes

// KeycloakIssuerService =======================================================================================================================================

/**
 * Keycloak as OID4VC Issuer
 *
 * https://www.keycloak.org/docs/latest/server_admin/index.html#_oid4vci
 */
class IssuerServiceKeycloak(val issuerCfg: IssuerConfig) :
    AbstractIssuerService<IssuerMetadataV10, CredentialOfferV10>("${issuerCfg.baseUrl}/realms/${issuerCfg.realm}") {

    val issuerBaseUrl = issuerCfg.baseUrl

    override suspend fun createCredentialOffer(
        ctx: LoginContext,
        subjectId: String,
        types: List<String>,
        userPin: String?
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

    override suspend fun getIssuerMetadata(): IssuerMetadataV10 {
        val metadataUrl = URI(getIssuerMetadataUrl()).toURL()
        log.info { "IssuerMetadataUrl: $metadataUrl" }
        return http.get(metadataUrl).body<IssuerMetadataV10>()
    }

    fun getRealmUsers(): List<UserRepresentation> {

        val realm = issuerCfg.realm
        val keycloak = KeycloakBuilder.builder()
            .serverUrl(issuerBaseUrl)
            .username(issuerCfg.adminUsername)
            .password(issuerCfg.adminPassword)
            .clientId("admin-cli")
            .realm("master")
            .build()

        log.info { "Connected to Keycloak realm: $realm" }

        // Fetch all users (paginated)
        val realmResource = keycloak.realm(realm)
        val usersResource = realmResource.users()

        val realmUsers = usersResource.list()
        keycloak.close()

        return realmUsers
    }

    // Private ---------------------------------------------------------------------------------------------------------

}