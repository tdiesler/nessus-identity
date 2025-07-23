package io.nessus.identity.service

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