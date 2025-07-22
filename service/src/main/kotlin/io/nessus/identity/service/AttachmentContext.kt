package io.nessus.identity.service

import java.util.concurrent.ConcurrentHashMap

// AttachmentKey =======================================================================================================

inline fun <reified T : Any> attachmentKey(name: String? = null): AttachmentKey<T> {
    return AttachmentKey(T::class.java, name)
}

data class AttachmentKey<T : Any>(val type: Class<T>, val name: String? = null) {

    override fun equals(other: Any?): Boolean {
        return other is AttachmentKey<*> &&
                other.type == this.type &&
                other.name == this.name
    }

    override fun hashCode(): Int {
        return 31 * type.hashCode() + (name?.hashCode() ?: 0)
    }
}

// AttachmentContext ===================================================================================================

@Suppress("UNCHECKED_CAST")
open class AttachmentContext() {

    constructor(attachments: Map<AttachmentKey<*>, Any> = mapOf()) : this() {
        valueStore.putAll(attachments)
    }

    private val valueStore = ConcurrentHashMap<AttachmentKey<*>, Any>()

    fun <T : Any> assertAttachment(key: AttachmentKey<T>): T {
        return valueStore[key] as? T ?: throw IllegalStateException("No $key")
    }

    fun <T : Any> getAttachment(key: AttachmentKey<T>): T? {
        return valueStore[key] as? T
    }

    fun getAttachments(): Map<AttachmentKey<*>, Any> {
        return valueStore.toMap()
    }

    fun hasAttachment(key: AttachmentKey<*>): Boolean {
        return valueStore.containsKey(key)
    }

    fun <T : Any> putAttachment(key: AttachmentKey<T>, value: T) {
        valueStore[key] = value
    }

    fun putAttachments(values: Map<AttachmentKey<*>, Any>) {
        valueStore.putAll(values)
    }

    fun <T : Any> removeAttachment(key: AttachmentKey<T>): T? {
        return valueStore.remove(key) as? T
    }
}