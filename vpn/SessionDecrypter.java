import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.InputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

import static javax.crypto.Cipher.DECRYPT_MODE;

public class SessionDecrypter {

    private SecretKey secretKey;
    private Cipher cipher;
    private IvParameterSpec ivSpec;

  //  public SessionDecrypter(String e_secretkey, String e_iv) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException {
 //       SessionKey key = new SessionKey(e_secretkey);
 //       this.secretKey = key.getSecretKey();

  //      byte[] ivbyte = Base64.getDecoder().decode(e_iv.getBytes());
  //      this.ivSpec = new IvParameterSpec(ivbyte);

  //      this.cipher = Cipher.getInstance("AES/CTR/NoPadding");
 //       cipher.init(DECRYPT_MODE, this.secretKey, this.ivSpec);
 //   }

    SessionDecrypter(byte[] key_b, byte[] iv_b) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException {
        int keyLength = key_b.length;
        this.secretKey = new SecretKeySpec(key_b, 0, keyLength, "AES");
        this.ivSpec = new IvParameterSpec(iv_b);
        this.cipher = Cipher.getInstance("AES/CTR/NoPadding");
        cipher.init(DECRYPT_MODE, this.secretKey, this.ivSpec);
    }


    public CipherInputStream openCipherInputStream(InputStream InputStream) {
        return new CipherInputStream(InputStream, cipher);
    }
}
