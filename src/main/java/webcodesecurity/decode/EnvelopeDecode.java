import java.io.FileInputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.security.PrivateKey;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class EnvelopeDecode {

    private static final String ENVELOPE_FILE = "uploads/envelope.dat";
    private static final String PRIVATE_KEY_FILE = "uploads/private.key";

    public SecretKey getAESKeyFromEnvelope() throws Exception {
		
		//개인키 파일 업로드
		ObjectInputStream o_private = new ObjectInputStream(new FileInputStream(PRIVATE_KEY_FILE));
		PrivateKey privateKey = (PrivateKey)o_private.readObject();
		o_private.close();

        // RSA 복호화용 Cipher 초기화
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);

        byte[] aesBytes = new byte[32]; // 대칭키(AES) 길이가 256비트(32byte)
        try (
            FileInputStream f_data = new FileInputStream(ENVELOPE_FILE);
            CipherInputStream cis = new CipherInputStream(f_data, cipher)
        ) {
            int b = cis.read(aesBytes); // 필요한 만큼만 읽기
            if (b != aesBytes.length) {
                throw new IOException("AES 키의 길이가 256비트가 아닙니다.");
            }
        }

        //AES 대칭키 반환
        return new SecretKeySpec(aesBytes, "AES");

	}

}
