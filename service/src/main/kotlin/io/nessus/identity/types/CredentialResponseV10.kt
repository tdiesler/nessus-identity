package io.nessus.identity.types

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonElement

@Serializable
data class CredentialResponseV10(
    @SerialName("credentials")
    val credentials: List<IssuedCredential>? = null,
    @SerialName("transaction_id")
    val transactionId: String? = null,
    @SerialName("interval")
    val interval: Long? = null,
    @SerialName("notification_id")
    val notificationId: String? = null,
) {
    @Serializable
    data class IssuedCredential(
        val credential: String,
    )
}

