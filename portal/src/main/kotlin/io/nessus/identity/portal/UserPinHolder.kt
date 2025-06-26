package io.nessus.identity.portal

import com.nimbusds.jwt.SignedJWT
import id.walt.oid4vc.data.CredentialOffer
import id.walt.oid4vc.data.OfferedCredential
import id.walt.oid4vc.data.OpenIDProviderMetadata
import id.walt.oid4vc.requests.AuthorizationRequest
import id.walt.oid4vc.responses.CredentialResponse
import io.nessus.identity.service.LoginContext
import java.lang.IllegalStateException
import java.time.Instant

object UserPinHolder {

    private var _userPin: String? = null

    fun maybeUserPin(): String? {
        if (_userPin == null) {
            _userPin = System.getenv("EBSI__PREAUTHORIZED_PIN")
        }
        return _userPin
    }

    fun getUserPin(): String {
        return maybeUserPin() ?: throw IllegalStateException("No user PIN")
    }

    fun setUserPin(pin: String) {
        _userPin = pin
    }
}