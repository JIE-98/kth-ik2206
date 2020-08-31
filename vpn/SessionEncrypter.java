import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.OutputStream;
import java.security.*;
import java.util.Base64;

import static javax.crypto.Cipher.ENCRYPT_MODE;

public class SessionEncrypter {

    private SessionKey sessionKey;
   // private SecretKey secretKey;
    private Cipher cipher;
    private IvParameterSpec ivSpec;

    //use sessionKey, IV to generate cipher
    public SessionEncrypter(int keylength) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, NoSuchPaddingException {
        SessionKey key = new SessionKey(keylength);
        SecretKey secretKey = key.getSecretKey();

        SecureRandom random = new SecureRandom();
        byte[] ivbyte = new byte[16];
        random.nextBytes(ivbyte);
        this.ivSpec = new IvParameterSpec(ivbyte);

    //    this.cipher = Cipher.getInstance("AES/CTR/NoPadding");
    //    cipher.init(ENCRYPT_MODE, secretKey, this.ivSpec);
    }

    // new
    public SessionEncrypter(byte[] key_b, byte[] iv) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException {
        int keyLength = key_b.length;
        SecretKey secretKey2= new SecretKeySpec(key_b, 0, keyLength, "AES");

        IvParameterSpec ivSpec = new IvParameterSpec(iv);

        this.cipher = Cipher.getInstance("AES/CTR/NoPadding");
        cipher.init(ENCRYPT_MODE, secretKey2, ivSpec);

    }


   public  byte[] getKeyBytes(){
        return sessionKey.getSecretKey().getEncoded();
   }

   public byte[] getIVBytes(){
        return ivSpec.getIV();
   }



    public String encodeKey(){
        byte[] keyByte = sessionKey.getSecretKey().getEncoded();
        return Base64.getEncoder().encodeToString(keyByte);
    }

    public String encodeIV(){
        return Base64.getEncoder().encodeToString(ivSpec.getIV());
    }

    public CipherOutputStream openCipherOutputStream(OutputStream outputStream) {
        return new CipherOutputStream(outputStream, cipher);
    }

}
