package io.nessus.identity.api

import id.walt.oid4vc.data.CredentialOffer

// IssuerApi ===========================================================================================================

interface IssuerApi {

    fun GetCredentialOffer(offerId: String): CredentialOffer

}