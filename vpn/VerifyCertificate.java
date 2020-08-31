import java.security.*;
import java.security.cert.*;


public class VerifyCertificate {

    public VerifyCertificate(X509Certificate cerUser, X509Certificate cerCA) throws CertificateException{
        // cerCA cerUser
        PublicKey publicKeyCA = cerCA.getPublicKey();
        String caDN = cerCA.getSubjectDN().getName();
        System.out.println("[caDN]:     "+caDN);
        String userDN = cerUser.getSubjectDN().getName();
        System.out.println("[userDN]:   "+userDN);

        boolean flag1 = false, flag2 = false, flag3 = false, flag4 = false;

        try{
            cerUser.verify(publicKeyCA);
            flag1 = true;
        }
        catch (NoSuchAlgorithmException | SignatureException | InvalidKeyException | NoSuchProviderException e) {
            e.printStackTrace();
        }
        try{
            cerCA.verify(publicKeyCA);
            flag4 = true;
        }
        catch (NoSuchAlgorithmException | SignatureException | InvalidKeyException | NoSuchProviderException e) {
            e.printStackTrace();
        }

        try{
            cerCA.checkValidity();
            flag2 = true;
        } catch (CertificateExpiredException | CertificateNotYetValidException e) {
            e.printStackTrace();
        }

        try{
            cerUser.checkValidity();
            flag3 = true;
        } catch (CertificateExpiredException | CertificateNotYetValidException e) {
            e.printStackTrace();
        }



        if(flag1&flag2&flag3&flag4){
            System.out.println("Verify certificate pass");
        }

    }




}
