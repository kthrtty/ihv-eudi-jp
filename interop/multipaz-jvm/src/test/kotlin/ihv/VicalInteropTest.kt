package ihv

import kotlinx.coroutines.runBlocking
import org.multipaz.mdoc.vical.SignedVical
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * 我々が出した VICAL を Multipaz 本家のパーサで検証する（issue #27・段階A）。
 *
 * VICAL は「IACA の集合」を配る仕組みで、**本番 IACA の秘密鍵を失った状況で、発行済みの
 * 資格証を無効にせずに新しいアンカーへ移行する**ために使う。ISO 18013-5 の IACA link
 * certificate は旧 IACA の秘密鍵で新 IACA に署名するので、失った後では使えない。
 *
 * ここで見るのは「Multipaz Wallet の Import VICAL が受け取る形になっているか」。
 * `SignedVical.parse` は署名を必ず検証する（disableSignatureVerification = false）。
 */
class VicalInteropTest {
    private fun vicalBytes(): ByteArray {
        val f = File("src/test/resources/vical.cbor")
        assertTrue(f.exists(), "vical.cbor が無い（run.sh が生成する）")
        return f.readBytes()
    }

    @Test
    fun `我々の VICAL を Multipaz がパースし署名を検証できる`() = runBlocking {
        val signed = SignedVical.parse(encodedSignedVical = vicalBytes(), disableSignatureVerification = false)
        val v = signed.vical
        println("vicalProvider = ${v.vicalProvider} / version = ${v.version}")
        assertEquals("1.0", v.version)
        assertTrue(v.certificateInfos.size >= 2, "旧 IACA と新 IACA の2枚以上が並ぶこと")

        // docType が9種そろっていること（我々の jp.go.* を要求できる形になっているか）
        v.certificateInfos.forEach { ci ->
            println("  IACA: ${ci.certificate.subject}  docTypes=${ci.docTypes.size}")
            assertTrue(ci.docTypes.contains("jp.go.pid.1"), "jp.go.pid.1 が含まれること")
            assertTrue(ci.docTypes.contains("jp.go.disaster.1"))
        }
    }

    @Test
    fun `改竄した VICAL は署名検証で弾かれる`() = runBlocking {
        val bytes = vicalBytes().copyOf()
        // 末尾（署名の一部）を1バイト反転させる
        bytes[bytes.size - 1] = (bytes[bytes.size - 1].toInt() xor 0xff).toByte()
        val threw = try {
            SignedVical.parse(encodedSignedVical = bytes, disableSignatureVerification = false)
            false
        } catch (e: Throwable) {
            println("期待どおり拒否: ${e::class.simpleName}")
            true
        }
        assertTrue(threw, "改竄した VICAL が通ってしまった（fail-closed でない）")
    }
}
