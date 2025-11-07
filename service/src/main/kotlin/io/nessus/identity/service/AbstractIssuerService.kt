package io.nessus.identity.service

import io.github.oshai.kotlinlogging.KotlinLogging
import io.nessus.identity.types.IssuerMetadata

abstract class AbstractIssuerService<IMType: IssuerMetadata>() : IssuerService<IMType> {

    val log = KotlinLogging.logger {}
}