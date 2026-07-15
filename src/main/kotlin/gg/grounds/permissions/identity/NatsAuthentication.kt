package gg.grounds.permissions.identity

import io.nats.client.Options
import java.io.IOException
import java.nio.file.Files
import java.nio.file.Path
import java.util.function.Supplier

internal class NatsTokenFileSupplier(private val tokenFile: Path) : Supplier<CharArray> {
    override fun get(): CharArray {
        val token =
            try {
                Files.readString(tokenFile).trim()
            } catch (exception: IOException) {
                throw IllegalStateException(
                    "Failed to read NATS authentication token (tokenFile=$tokenFile)",
                    exception,
                )
            } catch (exception: SecurityException) {
                throw IllegalStateException(
                    "Failed to read NATS authentication token (tokenFile=$tokenFile)",
                    exception,
                )
            }
        check(token.isNotEmpty()) {
            "NATS authentication token file is empty (tokenFile=$tokenFile)"
        }
        return token.toCharArray()
    }
}

internal fun buildNatsConnectionOptions(natsUrl: String, tokenFile: String?): Options {
    val builder = Options.builder().server(natsUrl)
    if (tokenFile != null) {
        require(tokenFile.isNotBlank()) { "NATS authentication token file path must not be blank" }
        builder.tokenSupplier(NatsTokenFileSupplier(Path.of(tokenFile)))
    }
    return builder.build()
}
