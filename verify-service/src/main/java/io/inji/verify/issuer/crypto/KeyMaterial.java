package io.inji.verify.issuer.crypto;

import com.fasterxml.jackson.databind.JsonNode;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.EdECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.EdECPoint;
import java.util.Arrays;
import java.util.Base64;
import java.util.Map;

/**
 * Key parsing and identity for DID document keys and credential signing keys.
 * Supported: EC (P-256, P-384, P-521, secp256k1), OKP Ed25519, RSA &gt;= 2048 bits, in JWK form;
 * Ed25519 in publicKeyMultibase form. Anything else is reported as UNSUPPORTED (not as malicious).
 */
public final class KeyMaterial {

    private static final Map<String, Integer> EC_COORD_BYTES = Map.of("P-256", 32, "P-384", 48, "P-521", 66, "secp256k1", 32);
    private static final Base64.Decoder B64URL = Base64.getUrlDecoder();
    private static final Base64.Encoder B64URL_ENC = Base64.getUrlEncoder().withoutPadding();
    private static final int MIN_RSA_BITS = 2048;

    private KeyMaterial() {
    }

    public static KeyInfo fromJwk(JsonNode jwk) throws KeyException {
        if (jwk == null || !jwk.isObject()) throw new KeyException(KeyException.Kind.INVALID, "MALFORMED_JWK");
        for (String priv : new String[]{"d", "p", "q", "dp", "dq", "qi", "k"}) {
            if (jwk.has(priv)) throw new KeyException(KeyException.Kind.INVALID, "PRIVATE_KEY_MATERIAL_PRESENT");
        }
        String kty = text(jwk, "kty");
        if (kty == null) throw new KeyException(KeyException.Kind.INVALID, "MALFORMED_JWK");
        switch (kty) {
            case "EC": {
                String crv = text(jwk, "crv");
                Integer len = crv == null ? null : EC_COORD_BYTES.get(crv);
                if (len == null) throw new KeyException(KeyException.Kind.UNSUPPORTED, "UNSUPPORTED_CURVE");
                String x = b64(jwk, "x", len), y = b64(jwk, "y", len);
                return new KeyInfo(kty, crv, thumbprint("{\"crv\":\"" + crv + "\",\"kty\":\"EC\",\"x\":\"" + x + "\",\"y\":\"" + y + "\"}"));
            }
            case "OKP": {
                String crv = text(jwk, "crv");
                if (!"Ed25519".equals(crv)) throw new KeyException(KeyException.Kind.UNSUPPORTED, "UNSUPPORTED_CURVE");
                String x = b64(jwk, "x", 32);
                return new KeyInfo(kty, crv, thumbprint("{\"crv\":\"Ed25519\",\"kty\":\"OKP\",\"x\":\"" + x + "\"}"));
            }
            case "RSA": {
                String n = b64(jwk, "n", -1), e = b64(jwk, "e", -1);
                BigInteger modulus = new BigInteger(1, B64URL.decode(n));
                if (modulus.bitLength() < MIN_RSA_BITS) throw new KeyException(KeyException.Kind.INVALID, "WEAK_RSA_KEY");
                return new KeyInfo(kty, null, thumbprint("{\"e\":\"" + e + "\",\"kty\":\"RSA\",\"n\":\"" + n + "\"}"));
            }
            default:
                throw new KeyException(KeyException.Kind.UNSUPPORTED, "UNSUPPORTED_KEY_TYPE");
        }
    }

    /** Ed25519 only: {@code z} + base58btc(0xed 0x01 + 32 bytes). */
    public static KeyInfo fromMultibase(String multibase) throws KeyException {
        if (multibase == null || multibase.length() < 2 || multibase.length() > 256 || multibase.charAt(0) != 'z') {
            throw new KeyException(KeyException.Kind.UNSUPPORTED, "UNSUPPORTED_KEY_ENCODING");
        }
        byte[] raw;
        try {
            raw = Base58.decode(multibase.substring(1));
        } catch (IllegalArgumentException e) {
            throw new KeyException(KeyException.Kind.INVALID, "MALFORMED_MULTIBASE");
        }
        if (raw.length == 34 && (raw[0] & 0xff) == 0xed && raw[1] == 0x01) {
            String x = B64URL_ENC.encodeToString(Arrays.copyOfRange(raw, 2, 34));
            return new KeyInfo("OKP", "Ed25519", thumbprint("{\"crv\":\"Ed25519\",\"kty\":\"OKP\",\"x\":\"" + x + "\"}"));
        }
        throw new KeyException(KeyException.Kind.UNSUPPORTED, "UNSUPPORTED_KEY_ENCODING");
    }

    /** Identity of a JCA key, e.g. the leaf certificate key from an SD-JWT x5c header. */
    public static KeyInfo fromPublicKey(PublicKey key) throws KeyException {
        if (key instanceof ECPublicKey ec) {
            int bits = ec.getParams().getCurve().getField().getFieldSize();
            String crv = switch (bits) {
                case 256 -> isSecp256k1(ec) ? "secp256k1" : "P-256";
                case 384 -> "P-384";
                case 521 -> "P-521";
                default -> null;
            };
            if (crv == null) throw new KeyException(KeyException.Kind.UNSUPPORTED, "UNSUPPORTED_CURVE");
            int len = EC_COORD_BYTES.get(crv);
            String x = B64URL_ENC.encodeToString(unsigned(ec.getW().getAffineX(), len));
            String y = B64URL_ENC.encodeToString(unsigned(ec.getW().getAffineY(), len));
            return new KeyInfo("EC", crv, thumbprint("{\"crv\":\"" + crv + "\",\"kty\":\"EC\",\"x\":\"" + x + "\",\"y\":\"" + y + "\"}"));
        }
        if (key instanceof EdECPublicKey ed) {
            if (!"Ed25519".equalsIgnoreCase(ed.getParams().getName())) throw new KeyException(KeyException.Kind.UNSUPPORTED, "UNSUPPORTED_CURVE");
            EdECPoint p = ed.getPoint();
            byte[] y = unsigned(p.getY(), 32);
            byte[] le = new byte[32];
            for (int i = 0; i < 32; i++) le[i] = y[31 - i];
            if (p.isXOdd()) le[31] |= (byte) 0x80;
            String x = B64URL_ENC.encodeToString(le);
            return new KeyInfo("OKP", "Ed25519", thumbprint("{\"crv\":\"Ed25519\",\"kty\":\"OKP\",\"x\":\"" + x + "\"}"));
        }
        if (key instanceof RSAPublicKey rsa) {
            if (rsa.getModulus().bitLength() < MIN_RSA_BITS) throw new KeyException(KeyException.Kind.INVALID, "WEAK_RSA_KEY");
            String n = B64URL_ENC.encodeToString(unsignedMinimal(rsa.getModulus()));
            String e = B64URL_ENC.encodeToString(unsignedMinimal(rsa.getPublicExponent()));
            return new KeyInfo("RSA", null, thumbprint("{\"e\":\"" + e + "\",\"kty\":\"RSA\",\"n\":\"" + n + "\"}"));
        }
        throw new KeyException(KeyException.Kind.UNSUPPORTED, "UNSUPPORTED_KEY_TYPE");
    }

    private static boolean isSecp256k1(ECPublicKey ec) {
        // secp256k1: a = 0, b = 7
        return ec.getParams().getCurve().getA().signum() == 0 && ec.getParams().getCurve().getB().equals(BigInteger.valueOf(7));
    }

    private static String text(JsonNode n, String f) {
        JsonNode v = n.get(f);
        return v != null && v.isTextual() ? v.asText() : null;
    }

    /** Validates base64url (no padding, canonical) and optional exact decoded length; returns the original text. */
    private static String b64(JsonNode jwk, String field, int expectedLen) throws KeyException {
        String v = text(jwk, field);
        if (v == null || v.isEmpty() || v.length() > 2048 || v.indexOf('=') >= 0) throw new KeyException(KeyException.Kind.INVALID, "MALFORMED_JWK");
        byte[] decoded;
        try {
            decoded = B64URL.decode(v);
        } catch (IllegalArgumentException e) {
            throw new KeyException(KeyException.Kind.INVALID, "MALFORMED_JWK");
        }
        if (!B64URL_ENC.encodeToString(decoded).equals(v)) throw new KeyException(KeyException.Kind.INVALID, "MALFORMED_JWK");
        if (expectedLen > 0 && decoded.length != expectedLen) throw new KeyException(KeyException.Kind.INVALID, "MALFORMED_JWK");
        return v;
    }

    private static String thumbprint(String canonicalJson) {
        try {
            byte[] d = MessageDigest.getInstance("SHA-256").digest(canonicalJson.getBytes(StandardCharsets.UTF_8));
            return B64URL_ENC.encodeToString(d);
        } catch (java.security.NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    private static byte[] unsigned(BigInteger v, int len) {
        byte[] b = v.toByteArray();
        byte[] out = new byte[len];
        int copy = Math.min(b.length, len);
        System.arraycopy(b, b.length - copy, out, len - copy, copy);
        return out;
    }

    private static byte[] unsignedMinimal(BigInteger v) {
        byte[] b = v.toByteArray();
        return b.length > 1 && b[0] == 0 ? Arrays.copyOfRange(b, 1, b.length) : b;
    }
}
