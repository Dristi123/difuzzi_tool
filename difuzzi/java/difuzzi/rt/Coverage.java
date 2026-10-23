package difuzzi.rt;

import java.io.*;
import java.lang.reflect.Method;

/**
 * Access to the JaCoCo agent that runs alongside Jazzer (restricted to the classes of A and B).
 * count() is used to notice inputs that reach new code; dump() is written at the end for the report.
 */
public final class Coverage {
    private static Object agent;
    private static Method getData;

    public static byte[] dump() throws Exception {
        if (agent == null) {
            agent = Class.forName("org.jacoco.agent.rt.RT").getMethod("getAgent").invoke(null);
            getData = agent.getClass().getMethod("getExecutionData", boolean.class);
        }
        return (byte[]) getData.invoke(agent, false);
    }

    /** Number of JaCoCo probes hit so far (probes only ever turn on, so growth means new coverage). */
    public static long count() {
        try {
            DataInputStream in = new DataInputStream(new ByteArrayInputStream(dump()));
            long hits = 0;
            int block;
            while ((block = in.read()) != -1) {
                switch (block) {
                    case 0x01: in.readChar(); in.readChar(); break;                     // header
                    case 0x10: in.readUTF(); in.readLong(); in.readLong(); break;        // session info
                    case 0x11:                                                           // execution data
                        in.readLong();
                        in.readUTF();
                        int n = readVarInt(in);
                        for (int i = 0; i < (n + 7) / 8; i++) hits += Integer.bitCount(in.readUnsignedByte());
                        break;
                    default: return hits;
                }
            }
            return hits;
        } catch (Exception e) {
            return -1;
        }
    }

    private static int readVarInt(DataInputStream in) throws IOException {
        int b = in.readUnsignedByte(), value = b & 0x7F, shift = 7;
        while ((b & 0x80) != 0) {
            b = in.readUnsignedByte();
            value |= (b & 0x7F) << shift;
            shift += 7;
        }
        return value;
    }
}
