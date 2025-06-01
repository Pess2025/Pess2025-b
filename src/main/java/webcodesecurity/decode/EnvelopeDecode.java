package webcodesecurity.decode;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.nio.file.Files;
import java.security.PrivateKey;
import java.util.Scanner;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class EnvelopeDecode { //사용자에게 업로드 받은 비밀키로 암호화 된 대칭키를 복호화, 대칭키 획득

    public SecretKey getAESKeyFromEnvelope(File privateKeyFile, File envelopeKeyFile) throws Exception {
		
		//개인키 파일 업로드
		ObjectInputStream o_private = new ObjectInputStream(new FileInputStream(privateKeyFile));
		PrivateKey privateKey = (PrivateKey)o_private.readObject();
		o_private.close();


        // 대칭키 복호화용 Cipher 초기화
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);

        //FileInputStream으로 암호화 된 대칭키 읽어서 CipherInputStream으로 복호화
        byte[] keyBytes = new byte[32]; // 대칭키(AES) 길이가 256비트(32byte)
        try (
            FileInputStream f_data = new FileInputStream(envelopeKeyFile);
            CipherInputStream cis = new CipherInputStream(f_data, cipher);
        ) {
            int read = cis.read(keyBytes);
            if (read != 32) {
                throw new IOException("잘못된 대칭키 길이입니다.");
            }
        }
        SecretKey secretKey = new SecretKeySpec(keyBytes, "AES"); //SecretKeySpec: byte 값이랑 + AES인거 매핑해서 SecretKey 객체로 전달

        return secretKey;
	}

}
