package io.nessus.identity.types

import com.nimbusds.jwt.SignedJWT
import id.walt.oid4vc.data.dif.PresentationSubmission

data class SubmissionBundle(
    val credentials: List<SignedJWT>,
    val submission: PresentationSubmission
)
