package io.nessus.identity.config

import io.nessus.identity.config.FeatureProfile.EBSI_V32
import io.nessus.identity.types.AttachmentKey
import io.nessus.identity.types.AttachmentSupport
import io.nessus.identity.types.attachmentKey

enum class FeatureProfile(val value: String) {
    DEFAULT("default"),
    EBSI_V32("ebsi_v32"),
}

object Features: AttachmentSupport() {

    // Automatically fetch Credential on CredentialOffer receive
    val CREDENTIAL_OFFER_AUTO_FETCH = attachmentKey<Boolean>("CREDENTIAL_OFFER_AUTO_FETCH")
    val CREDENTIAL_OFFER_STORE = attachmentKey<Boolean>("CREDENTIAL_OFFER_STORE")

    private lateinit var currentProfile: FeatureProfile

    fun initProfile(profile: FeatureProfile) {
        currentProfile = profile
        when(profile) {
            EBSI_V32 -> {
                putAttachment(CREDENTIAL_OFFER_AUTO_FETCH, true)
                putAttachment(CREDENTIAL_OFFER_STORE, false)
            }
            else -> {
                putAttachment(CREDENTIAL_OFFER_AUTO_FETCH, false)
                putAttachment(CREDENTIAL_OFFER_STORE, true)
            }
        }
    }

    fun isEnabled(key: AttachmentKey<Boolean>): Boolean {
        return getAttachment(key) ?: false
    }

    fun getProfile(): FeatureProfile {
        return currentProfile
    }

    fun isProfile(profile: FeatureProfile): Boolean {
        return currentProfile == profile
    }
}