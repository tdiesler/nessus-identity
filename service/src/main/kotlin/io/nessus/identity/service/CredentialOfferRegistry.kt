package io.nessus.identity.service

import io.github.oshai.kotlinlogging.KotlinLogging
import io.nessus.identity.types.CredentialOffer

data class CredentialOfferRecord(
    val credOffer:  CredentialOffer?,
    val userPin:    String?,
)

object CredentialOfferRegistry {

    val log = KotlinLogging.logger {}

    // Maps Pre-Authorization Codes to CredentialOfferRecord
    private val registry = mutableMapOf<String, CredentialOfferRecord>()

    fun isEBSIPreAuthorizedType(credType: String): Boolean {
        return credType.startsWith("CT") && credType.contains("PreAuthorised")
    }

    fun assertCredentialOfferRecord(authCode: String): CredentialOfferRecord {
        val cor = getCredentialOfferRecord(authCode)
        return cor ?: throw IllegalStateException("No CredentialOffer record")
    }

    fun getCredentialOfferRecord(authCode: String): CredentialOfferRecord? {
        return registry[authCode]
    }

    fun hasCredentialOfferRecord(authCode: String): Boolean {
        return registry.containsKey(authCode)
    }

    fun putCredentialOfferRecord(authCode: String, credOffer: CredentialOffer?, userPin: String?) {
        registry[authCode] = CredentialOfferRecord(credOffer, userPin)
    }

    fun removeCredentialOfferRecord(authCode: String): CredentialOfferRecord? {
        return registry.remove(authCode)
    }
}