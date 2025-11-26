package io.nessus.identity.service

import io.github.oshai.kotlinlogging.KotlinLogging

abstract class AbstractIssuerService() : IssuerService {

    val log = KotlinLogging.logger {}
}