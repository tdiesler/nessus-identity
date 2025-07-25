package io.nessus.identity.types

import id.walt.oid4vc.data.dif.InputDescriptor
import id.walt.oid4vc.data.dif.InputDescriptorConstraints
import id.walt.oid4vc.data.dif.InputDescriptorField
import id.walt.oid4vc.data.dif.PresentationDefinition
import id.walt.oid4vc.data.dif.VCFormatDefinition
import id.walt.oid4vc.util.ShortIdUtils
import id.walt.w3c.utils.VCFormat
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlin.uuid.ExperimentalUuidApi
import kotlin.uuid.Uuid

@OptIn(ExperimentalUuidApi::class)
class PresentationDefinitionBuilder() {

    private var id: String = ShortIdUtils.randomSessionId()
    private val formats = mutableMapOf<VCFormat, VCFormatDefinition>()
    private val inputDescriptors = mutableListOf<InputDescriptor>()

    fun withId(id: String): PresentationDefinitionBuilder {
        this.id = id
        return this
    }

    fun withFormat(vcFormat: VCFormat, vcFormatDef: VCFormatDefinition): PresentationDefinitionBuilder {
        this.formats[vcFormat] = vcFormatDef
        return this
    }

    fun withInputDescriptor(inp: InputDescriptor): PresentationDefinitionBuilder {
        this.inputDescriptors.add(inp)
        return this
    }

    fun withInputDescriptorForType(vcType: String, id: String? = null): PresentationDefinitionBuilder {
        val inp = InputDescriptor(
            id = id ?: "${Uuid.random()}",
            format = mapOf(VCFormat.jwt_vc to VCFormatDefinition(alg = setOf("ES256"))),
            constraints = InputDescriptorConstraints(
                fields = listOf(
                    InputDescriptorField(
                        path = listOf("$.vc.type"),
                        filter = buildJsonObject {
                            put("type", JsonPrimitive("array"))
                            put("contains", buildJsonObject {
                                put("const", JsonPrimitive(vcType))
                            })
                        }
                    )
                ),
            ),
        )
        this.inputDescriptors.add(inp)
        return this
    }

    fun build(): PresentationDefinition {
        if (formats.isEmpty()) {
            formats[VCFormat.jwt_vc] = VCFormatDefinition(alg = setOf("ES256"))
            formats[VCFormat.jwt_vp] = VCFormatDefinition(alg = setOf("ES256"))
        }
        val vpDef = PresentationDefinition(
            id = id,
            format = formats,
            inputDescriptors = inputDescriptors,
        )
        return vpDef
    }
}