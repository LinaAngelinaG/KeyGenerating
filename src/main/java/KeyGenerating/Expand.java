package KeyGenerating;

import HMAC.HMAC;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;

public class Expand {
    private HMAC mac = new HMAC();

    public HMAC getMac() {
        return mac;
    }

    public byte[] HkdfExpand(byte[] PRK, byte[] lastKey, byte[] CTX, int i) throws NoSuchAlgorithmException, IOException {
        if (lastKey == null) lastKey = "".getBytes(); //здесь еще посмотреть - проверить
        mac.setKey(PRK);
        return mac.ComputeMac(concatenateByteArray(lastKey, CTX, (byte)i));
    }

    private byte[] concatenateByteArray(byte[] first, byte[] second,byte third) throws IOException {
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        outputStream.write(first);
        outputStream.write(second);
        outputStream.write(third);
        return outputStream.toByteArray();
    }

    public Expand() throws NoSuchAlgorithmException {
    }
}
