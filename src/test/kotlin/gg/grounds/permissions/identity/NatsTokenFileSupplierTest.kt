package gg.grounds.permissions.identity

import java.nio.file.Files
import java.nio.file.Path
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir

class NatsTokenFileSupplierTest {
    @TempDir lateinit var tempDir: Path

    @Test
    fun readsProjectedTokenFileForEveryAuthenticationAttempt() {
        val tokenFile = tempDir.resolve("token")
        Files.writeString(tokenFile, "first-token\n")
        val supplier = NatsTokenFileSupplier(tokenFile)

        assertArrayEquals("first-token".toCharArray(), supplier.get())

        Files.writeString(tokenFile, "rotated-token\n")

        assertArrayEquals("rotated-token".toCharArray(), supplier.get())
    }

    @Test
    fun failsClearlyWhenConfiguredTokenFileIsMissing() {
        val tokenFile = tempDir.resolve("missing-token")
        val supplier = NatsTokenFileSupplier(tokenFile)

        val exception = assertThrows(IllegalStateException::class.java) { supplier.get() }

        assertTrue(exception.message!!.contains("Failed to read NATS authentication token"))
        assertTrue(exception.message!!.contains(tokenFile.toString()))
    }

    @Test
    fun failsClearlyWhenConfiguredTokenFileIsUnreadable() {
        val supplier = NatsTokenFileSupplier(tempDir)

        val exception = assertThrows(IllegalStateException::class.java) { supplier.get() }

        assertTrue(exception.message!!.contains("Failed to read NATS authentication token"))
        assertTrue(exception.message!!.contains(tempDir.toString()))
    }

    @Test
    fun rejectsBlankTokenFileContents() {
        val tokenFile = tempDir.resolve("token")
        Files.writeString(tokenFile, " \n")
        val supplier = NatsTokenFileSupplier(tokenFile)

        val exception = assertThrows(IllegalStateException::class.java) { supplier.get() }

        assertTrue(exception.message!!.contains("NATS authentication token file is empty"))
        assertTrue(exception.message!!.contains(tokenFile.toString()))
    }
}
