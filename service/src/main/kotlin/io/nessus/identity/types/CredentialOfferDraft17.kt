package io.nessus.identity.types

import io.nessus.identity.service.OID4VCIUtils
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/*
    https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-credential-offer-endpoint
*/
@Serializable
data class CredentialOfferDraft17(
    @SerialName("credential_issuer")
    override val credentialIssuer: String,

    @SerialName("credential_configuration_ids")
    val credentialConfigurationIds: List<String>,

    @SerialName("grants")
    override val grants: Grants? = null
) : CredentialOffer() {

    // [TODO #283] Remove 'types' from CredentialOfferDraft17
    // https://github.com/tdiesler/nessus-identity/issues/283
    override fun getTypes(): List<String> {
        return credentialConfigurationIds
    }
}

@Serializable
data class Grants(
    @SerialName("authorization_code")
    val authorizationCode: AuthorizationCodeGrant? = null,

    @SerialName("urn:ietf:params:oauth:grant-type:pre-authorized_code")
    val preAuthorizedCode: PreAuthorizedCodeGrant? = null
)

@Serializable
data class AuthorizationCodeGrant(
    @SerialName("issuer_state")
    val issuerState: String? = null,

    @SerialName("authorization_server")
    val authorizationServer: String? = null,

    // [TODO #275] How to know the client_id for the Authorization Request
    // https://github.com/tdiesler/nessus-identity/issues/275
    @SerialName("client_id")
    val clientId: String? = null,
)

@Serializable
data class PreAuthorizedCodeGrant(
    @SerialName("pre-authorized_code")
    val preAuthorizedCode: String,

    @SerialName("tx_code")
    val txCode: TransactionCode? = null
)

@Serializable
data class TransactionCode(
    val length: Int? = null,
    @SerialName("input_mode")
    val inputMode: String? = null,
    val description: String? = null
)
