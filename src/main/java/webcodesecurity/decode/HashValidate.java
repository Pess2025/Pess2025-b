import java.security.PublicKey;
import java.security.Signature;

public class HashValidate {
	
	//signatureBytes 암호화된 해시 값
    public boolean validate(String passwordText, byte[] signatureBytes, PublicKey publickey) throws Exception {
        
    	//공개키 불러오기
        PublicKey publicKey = publickey;

        // 2. Signature 객체 publicKey로 복호화
        Signature sig = Signature.getInstance("SHA256withRSA");
        sig.initVerify(publicKey);
        sig.update(passwordText.getBytes("UTF-8"));


        // 3. 서명 검증
        return sig.verify(signatureBytes);
    }

}