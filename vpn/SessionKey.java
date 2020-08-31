
import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

public class SessionKey {
    private SecretKey secretKey;

    //generate key, Length to SecretKey
    public SessionKey (int keyLength) throws NoSuchAlgorithmException {
        KeyGenerator key1 = KeyGenerator.getInstance("AES");
        key1.init(keyLength);
        this.secretKey = key1.generateKey();
    }

    //decode String(Base64) to SecretKey
    public SessionKey (String keyString) {
        byte[] keyByte = Base64.getDecoder().decode(keyString.getBytes());
        //Decodes a Base64 encoded String into a byte array
        int keyLength = keyByte.length;
        this.secretKey = new SecretKeySpec(keyByte, 0, keyLength, "AES");
        //Construct secret key from the given byte array.
    }


    // get SecretKey
    public SecretKey getSecretKey() {
        return secretKey;
    }

    // encode secretKey to keyString
    public String encodeKey() {
        byte[] keyByte = secretKey.getEncoded();
        return Base64.getEncoder().encodeToString(keyByte);
    }






//    public static void main(String[] args) throws NoSuchAlgorithmException {
//
//        SessionKey key1 = new SessionKey(128);
//        SessionKey key2 = new SessionKey(key1.encodeKey());
//        if (key1.getSecretKey().equals(key2.getSecretKey())) {
//            System.out.println("Pass");
//        }
//        else {
//            System.out.println("Fail");
//        }
//    }
}
