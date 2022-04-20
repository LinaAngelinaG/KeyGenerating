package KeyGenerating;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;

public class HKDF {
    private Expand expand = new Expand();
    private Extract extract = new Extract();

    public byte[] KDF(byte[] XTS, byte[] SKM, byte[] CTX, int length) throws IOException, NoSuchAlgorithmException {

        int numberOfKeys = length/expand.getMac().getByteBlockSize();
        ByteArrayOutputStream result = new ByteArrayOutputStream();
        byte[] KEYi = null;
        byte[] PRK = extract.HkdfExtract(XTS,SKM);
        for(int i = 0; i<numberOfKeys;++i){
            KEYi = expand.HkdfExpand(PRK,KEYi,CTX,i);
            result.write(KEYi);
        }
        return result.toByteArray();
    }

    public HKDF() throws NoSuchAlgorithmException {
    }
}
