package io.nessus.identity.types

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
data class CredentialResponseV0(
    @SerialName("credentials")
    val credentials: List<IssuedCredential>? = null,
    @SerialName("transaction_id")
    val transactionId: String? = null,
    @SerialName("interval")
    val interval: Long? = null,
    @SerialName("notification_id")
    val notificationId: String? = null,
): CredentialResponse() {

    @Serializable
    data class IssuedCredential(
        val credential: String,
    )
}

