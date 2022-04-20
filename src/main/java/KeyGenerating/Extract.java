package KeyGenerating;

import HMAC.HMAC;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;

public class Extract {
    private HMAC mac = new HMAC();

    public byte[] HkdfExtract(byte[] XTS, byte[] SKM) throws IOException, NoSuchAlgorithmException {
        mac.setKey(XTS);
        return mac.ComputeMac(SKM);
    }

    public Extract() throws NoSuchAlgorithmException {
    }
}
