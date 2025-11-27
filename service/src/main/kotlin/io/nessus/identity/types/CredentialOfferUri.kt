package io.nessus.identity.types

enum class OfferUriType(val value: String) {
    URI("uri"),
    QR_CODE("qr-code");
    override fun toString() = value
}

class CredentialOfferUri(val configId: String) {

    var preAuthorized: Boolean? = null
    var userId: String? = null
    var type: OfferUriType? = null

    fun withPreAuthorized(preAuthorized: Boolean): CredentialOfferUri {
        this.preAuthorized = preAuthorized
        return this
    }

    fun withUserId(userId: String): CredentialOfferUri {
        this.userId = userId
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
        userId?.also { result["user_id"] = "$userId" }
        type?.also { result["type"] = "$type" }
        return result
    }
}