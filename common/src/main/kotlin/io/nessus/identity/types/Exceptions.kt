package io.nessus.identity.types

class VerificationException(val vcId: String, message: String) : RuntimeException(message)
