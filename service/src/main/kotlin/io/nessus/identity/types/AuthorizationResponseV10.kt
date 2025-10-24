package io.nessus.identity.types

import id.walt.oid4vc.data.dif.PresentationSubmission
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.*

@Serializable
data class AuthorizationResponseV10(
    @SerialName("vp_token")
    val vpToken: String,

    @SerialName("presentation_submission")
    val presentationSubmission: PresentationSubmission,

    val state: String? = null
) {
    fun toJson() = Json.encodeToString(this)
    fun toJsonObj() = Json.encodeToJsonElement(this).jsonObject

    companion object {
        val jsonInst = Json { ignoreUnknownKeys = true}
        fun fromJson(json: String) = jsonInst.decodeFromString<AuthorizationResponseV10>(json)
        fun fromJson(json: JsonObject) = jsonInst.decodeFromJsonElement<AuthorizationResponseV10>(json)

        fun fromHttpParameters(params: Map<String, String>): AuthorizationResponseV10 {
            val submissionParam = params["presentation_submission"] ?: error("No presentation_submission")
            val submission = Json.decodeFromString<PresentationSubmission>(submissionParam)
            val authRes = AuthorizationResponseV10(
                vpToken = params["vp_token"] ?: error("No vp_token"),
                presentationSubmission = submission,
                state = params["state"],
            )
            return authRes
        }
    }
}
