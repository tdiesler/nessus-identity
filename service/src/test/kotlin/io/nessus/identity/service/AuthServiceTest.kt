package io.nessus.identity.service

import io.kotest.common.runBlocking
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.string.shouldEndWith
import io.nessus.identity.waltid.Max
import org.junit.jupiter.api.Test

class AuthServiceTest : AbstractServiceTest() {

    @Test
    fun authMetadata() {
        runBlocking {
            val max = OIDContext(login(Max).withDidInfo())
            val authSvc = AuthServiceEbsi32.create(max)

            val metadataUrl = authSvc.getAuthMetadataUrl()
            metadataUrl.shouldEndWith("/auth/${max.targetId}/.well-known/openid-configuration")

            val jsonObj = authSvc.getAuthMetadata()
            jsonObj.shouldNotBeNull()
        }
    }
}