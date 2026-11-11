package io.inji.verify.issuer.crypto;

import java.math.BigInteger;
import java.util.Arrays;

/** Base58 (Bitcoin alphabet) decoding, used for multibase 'z' keys. */
final class Base58 {
    private static final String ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    private static final BigInteger BASE = BigInteger.valueOf(58);

    private Base58() {
    }

    static byte[] decode(String s) {
        BigInteger n = BigInteger.ZERO;
        for (int i = 0; i < s.length(); i++) {
            int d = ALPHABET.indexOf(s.charAt(i));
            if (d < 0) throw new IllegalArgumentException("bad base58 char");
            n = n.multiply(BASE).add(BigInteger.valueOf(d));
        }
        byte[] bytes = n.toByteArray();
        if (bytes.length > 1 && bytes[0] == 0) bytes = Arrays.copyOfRange(bytes, 1, bytes.length);
        if (n.signum() == 0) bytes = new byte[0];
        int zeros = 0;
        while (zeros < s.length() && s.charAt(zeros) == '1') zeros++;
        byte[] out = new byte[zeros + bytes.length];
        System.arraycopy(bytes, 0, out, zeros, bytes.length);
        return out;
    }
}
