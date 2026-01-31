package io.nessus.identity.types

enum class OfferUriType(val value: String) {
    QR("qr"),
    URI("uri"),
    URI_AND_QR("uri+qr");
    override fun toString() = value
}

class CredentialOfferUri(val configId: String) {

    var preAuthorized: Boolean? = null
    var targetUser: String? = null
    var type: OfferUriType? = null

    fun withPreAuthorized(preAuthorized: Boolean): CredentialOfferUri {
        this.preAuthorized = preAuthorized
        return this
    }

    fun withTargetUser(targetUser: String): CredentialOfferUri {
        this.targetUser = targetUser
        return this
    }

    fun withType(type: OfferUriType): CredentialOfferUri {
        this.type = type
        return this
    }

    fun getUrlQuery(): String {
        return parameters().map{ (k, v) -> "$k=$v" }.joinToString("&")
    }

    fun parameters(): Map<String, String> {
        val result = mutableMapOf("credential_configuration_id" to configId)
        preAuthorized?.also { result["pre_authorized"] = "$preAuthorized" }
        targetUser?.also { result["target_user"] = "$targetUser" }
        type?.also { result["type"] = "$type" }
        return result
    }
}