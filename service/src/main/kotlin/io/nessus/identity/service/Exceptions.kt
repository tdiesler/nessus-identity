package io.nessus.identity.service

class VerificationException(val vcId: String, message: String) : RuntimeException(message)
