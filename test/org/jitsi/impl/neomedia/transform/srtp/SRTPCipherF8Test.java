package org.jitsi.impl.neomedia.transform.srtp;

import static org.junit.Assert.*;
import java.util.Arrays;
import javax.xml.bind.DatatypeConverter;
import org.bouncycastle.crypto.general.*;
import org.junit.*;
import org.bouncycastle.crypto.fips.WrapAESEngine;

public class SRTPCipherF8Test
{
    // RFC 3711 AES F8 Tests vectors
    public static final byte[] TV_Key =
        DatatypeConverter.parseHexBinary("234829008467be186c3de14aae72d62c");

    public static final byte[] TV_Salt =
        DatatypeConverter.parseHexBinary("32f2870d");

    public static final byte[] TV_IV =
        DatatypeConverter.parseHexBinary("006e5cba50681de55c621599d462564a");

    public static final byte[] TV_Plain =
        DatatypeConverter.parseHexBinary("70736575646f72616e646f6d6e657373"
            + "20697320746865206e65787420626573" + "74207468696e67");

    public static final byte[] TV_Cipher_AES =
        DatatypeConverter.parseHexBinary("019ce7a26e7854014a6366aa95d4eefd"
            + "1ad4172a14f9faf455b7f1d4b62bd08f" + "562c0eef7c4802");

    /**
     * Validate our F8 mode implementation with tests vectors provided in
     * RFC3711
     * 
     * @throws Exception
     */
    @Test
    public void testAES() throws Exception
    {
        SRTPCipherF8 cipher = new SRTPCipherF8(new WrapAESEngine());
        cipher.init(TV_Key, TV_Salt);
        byte[] data = Arrays.copyOf(TV_Plain, TV_Plain.length);
        byte[] iv = Arrays.copyOf(TV_IV, TV_IV.length);
        cipher.process(data, 0, data.length, iv);

        assertArrayEquals(data, TV_Cipher_AES);
    }
}
