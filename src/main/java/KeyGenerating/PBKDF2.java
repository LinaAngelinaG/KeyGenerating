package KeyGenerating;

import HMAC.HMAC;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;

public class PBKDF2 {
    private HMAC mac = new HMAC();
    private int numberOfIterations = 10000;

    public byte[] KDF(byte[] password, byte[] salt, int keyLength) throws IOException, NoSuchAlgorithmException {
        int numberOfIter = keyLength / mac.getByteBlockSize();
        ByteArrayOutputStream result = new ByteArrayOutputStream();
        mac.setKey(password);
        for (int i = 1; i <= numberOfIter; ++i) {
            result.write(makeIterations(salt, i));
        }
        return result.toByteArray();
    }

    private byte[] makeIterations(byte[] salt, int i) throws IOException, NoSuchAlgorithmException {
        ByteArrayOutputStream newSalt = new ByteArrayOutputStream();
        newSalt.write(salt);
        newSalt.write((byte) i);
        salt = newSalt.toByteArray();
        XOR xor = new XOR();
        for (int j = 0; j < numberOfIterations; ++j) {
            salt = mac.ComputeMac(salt);
            xor.update(salt);
        }
        return xor.digest();
    }

    public PBKDF2() throws NoSuchAlgorithmException {
    }
}