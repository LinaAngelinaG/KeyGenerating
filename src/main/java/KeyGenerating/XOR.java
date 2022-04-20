package KeyGenerating;


import java.util.Arrays;

public class XOR {
    private byte[] current = null;

    public void update(byte[] array){
        if(current == null)
            current = Arrays.copyOf(array,array.length);
        else
            HMAC.XOR.CountResult(current,array);
    }

    public byte[] digest(){
        return current;
    }
}
