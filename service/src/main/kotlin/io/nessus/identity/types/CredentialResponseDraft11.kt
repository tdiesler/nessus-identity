package io.nessus.identity.types

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
data class CredentialResponseDraft11(
    @SerialName("format")
    val format: String,
    @SerialName("credential")
    val credential: String? = null,
    @SerialName("acceptance_token")
    val acceptanceToken: String? = null,
    @SerialName("c_nonce")
    val cNonce: String? = null,
    @SerialName("c_nonce_expires_in")
    val cNonceExpiresIn: String? = null,
): CredentialResponse()

