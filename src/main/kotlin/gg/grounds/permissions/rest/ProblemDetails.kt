package gg.grounds.permissions.rest

import com.fasterxml.jackson.annotation.JsonInclude
import jakarta.ws.rs.core.HttpHeaders
import java.net.URI
import java.util.UUID

@JsonInclude(JsonInclude.Include.NON_NULL)
data class ProblemDetails(
    val type: URI,
    val title: String,
    val status: Int,
    val detail: String,
    val instance: URI,
    val requestId: String,
    val error: String? = null,
    val reason: String? = null,
)

object RequestIdResolver {
    private const val REQUEST_ID_HEADER = "X-Request-ID"
    private const val MAXIMUM_REQUEST_ID_LENGTH = 128

    fun resolve(headers: HttpHeaders): String =
        headers.getHeaderString(REQUEST_ID_HEADER)?.trim()?.takeIf(::isSafe)
            ?: UUID.randomUUID().toString()

    private fun isSafe(value: String): Boolean =
        value.isNotEmpty() &&
            value.length <= MAXIMUM_REQUEST_ID_LENGTH &&
            value.all { it.isLetterOrDigit() || it in "._:-" }
}
