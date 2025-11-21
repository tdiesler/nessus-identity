package io.nessus.identity.types

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
data class CredentialRequestDraft11(
    val format: String? = null,
    val types: List<String>? = null,
    val proof: Proof? = null,
): CredentialRequest() {

    @Serializable
    data class Proof(
        @SerialName("proof_type")
        val proofType: String? = null,
        val jwt: String? = null,
    )
}