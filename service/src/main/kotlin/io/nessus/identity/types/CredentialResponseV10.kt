package io.nessus.identity.types

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.decodeFromJsonElement
import kotlinx.serialization.json.encodeToJsonElement
import kotlinx.serialization.json.jsonObject

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

    fun toJson() = Json.encodeToString(this)
    fun toJsonObj() = Json.encodeToJsonElement(this).jsonObject

    companion object {
        val jsonInst = Json { ignoreUnknownKeys = true}
        fun fromJson(json: String) = jsonInst.decodeFromString<CredentialResponseV10>(json)
        fun fromJson(json: JsonObject) = jsonInst.decodeFromJsonElement<CredentialResponseV10>(json)
    }

    @Serializable
    data class IssuedCredential(
        val credential: String,
    )
}

