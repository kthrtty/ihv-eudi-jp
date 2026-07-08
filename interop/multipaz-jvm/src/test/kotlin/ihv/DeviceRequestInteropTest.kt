package ihv

// 段階A（issue #13）: 我々（IHV, Node）が生成した Annex C DeviceRequest を、
// Multipaz 本家（org.multipaz:multipaz-jvm）の DeviceRequestParser でパース・検証する
// クロス実装テスト。エミュレータ不要・決定的。fixture.json は
// `node scripts/export-multipaz-fixture.mjs` が生成（我々の verifier の実出力）。
//
// これが緑になる＝(1) 我々の DeviceRequest CBOR を Multipaz が読める、
// (2) docType/namespaces/要素が一致、(3) Multipaz が我々の readerAuth 署名を
// ReaderAuthentication 再構成のうえ検証して readerAuthenticated=true にする
// ＝「自己ループでなく外部実装との適合」を満たす。
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.*
import org.multipaz.mdoc.request.DeviceRequestParser
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class DeviceRequestInteropTest {

    private fun hexToBytes(s: String): ByteArray =
        ByteArray(s.length / 2) { ((s[it * 2].digitToInt(16) shl 4) or s[it * 2 + 1].digitToInt(16)).toByte() }

    private fun loadFixture(): JsonObject =
        Json.parseToJsonElement(
            this::class.java.getResource("/fixture.json")!!.readText()
        ).jsonObject

    @Test
    fun `Multipaz parses our Annex C DeviceRequest and verifies our readerAuth`() = runBlocking {
        val fx = loadFixture()
        val deviceRequest = hexToBytes(fx["deviceRequestHex"]!!.jsonPrimitive.content)
        val sessionTranscript = hexToBytes(fx["sessionTranscriptHex"]!!.jsonPrimitive.content)
        val expected = fx["expected"]!!.jsonObject

        val parsed = DeviceRequestParser(deviceRequest, sessionTranscript).parse()
        assertEquals(1, parsed.docRequests.size, "one docRequest")
        val dr = parsed.docRequests[0]

        // (2) 構造の一致: docType / namespaces / 要素名
        assertEquals(expected["docType"]!!.jsonPrimitive.content, dr.docType, "docType matches")
        val expectedNs = expected["namespaces"]!!.jsonArray.map { it.jsonPrimitive.content }.toSet()
        assertEquals(expectedNs, dr.namespaces.toSet(), "namespaces match")
        val entryNames = expected["entryNames"]!!.jsonObject
        for (ns in dr.namespaces) {
            val ours = entryNames[ns]!!.jsonObject.keys
            assertEquals(ours, dr.getEntryNames(ns).toSet(), "entry names match for $ns")
        }

        // (3) 本命: Multipaz が我々の readerAuth 署名を検証（ReaderAuthentication を独立再構成）
        assertTrue(dr.readerAuth != null, "readerAuth present in the request")
        assertTrue(dr.readerCertificateChain != null, "reader certificate chain present")
        assertTrue(
            dr.readerAuthenticated,
            "Multipaz must verify OUR readerAuth COSE_Sign1 signature over the reconstructed ReaderAuthentication"
        )
    }

    @Test
    fun `Multipaz rejects a tampered request (items swapped, old readerAuth kept)`() = runBlocking {
        val fx = Json.parseToJsonElement(
            this::class.java.getResource("/fixture-tampered.json")!!.readText()
        ).jsonObject
        val deviceRequest = hexToBytes(fx["deviceRequestHex"]!!.jsonPrimitive.content)
        val sessionTranscript = hexToBytes(fx["sessionTranscriptHex"]!!.jsonPrimitive.content)

        // 署名不一致は parse 中に例外 or readerAuthenticated=false のどちらか — 両方許容し「認証されない」ことを確認
        val authenticated = try {
            DeviceRequestParser(deviceRequest, sessionTranscript).parse().docRequests[0].readerAuthenticated
        } catch (e: Throwable) {
            false
        }
        assertEquals(false, authenticated, "tampered items with the old signature must NOT authenticate the reader")
    }
}
