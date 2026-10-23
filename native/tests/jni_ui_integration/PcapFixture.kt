import com.netcontrol.app.capture.PcapWriter
import java.io.FileOutputStream

fun main(args: Array<String>) {
    require(args.size == 1)
    val output = FileOutputStream(args[0])
    PcapWriter(output).use { writer ->
        val ipv4 = ByteArray(28).apply {
            this[0] = 0x45; this[2] = 0; this[3] = 28; this[8] = 64; this[9] = 17
            this[12] = 10; this[15] = 2; this[16] = 8; this[19] = 8
            this[20] = 0x30; this[21] = 0x39; this[22] = 0; this[23] = 53; this[25] = 8
        }
        val ipv6 = ByteArray(48).apply {
            this[0] = 0x60; this[5] = 8; this[6] = 17; this[7] = 64
            this[8] = 0x20; this[9] = 1; this[23] = 1
            this[24] = 0x20; this[25] = 1; this[39] = 2
            this[40] = 0x30; this[41] = 0x39; this[42] = 0; this[43] = 53; this[45] = 8
        }
        writer.writePacket(1_234L, ipv4)
        writer.writePacket(2_345L, ipv6)
    }
}
