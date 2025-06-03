package webcodesecurity.decode;

import org.springframework.web.multipart.MultipartFile;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Arrays;
import java.util.Scanner;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.SecretKey;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import javax.crypto.spec.SecretKeySpec;

public class EnvelopeDecode implements Serializable { //사용자에게 업로드 받은 비밀키로 암호화 된 대칭키를 복호화, 대칭키 획득
    private static final long serialVersionUID = 1L;

    public SecretKey getAESKeyFromEnvelope(MultipartFile file, File envelopeKeyFile) throws Exception {

        ObjectInputStream ois = new ObjectInputStream(file.getInputStream());
        PrivateKey privateKey = (PrivateKey) ois.readObject();
        ois.close();

        System.out.println("[DEBUG] 개인키 디코딩 완료");

        // 2. 암호화된 AES 키 파일 읽기
        byte[] encryptedKeyBytes = Files.readAllBytes(envelopeKeyFile.toPath());
        System.out.println("[DEBUG] 암호화된 AES 키 파일 읽기 완료. 길이: " + encryptedKeyBytes.length);

        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        OAEPParameterSpec oaepParams = new OAEPParameterSpec(
                "SHA-256",
                "MGF1",
                MGF1ParameterSpec.SHA256,
                PSource.PSpecified.DEFAULT
        );
        cipher.init(Cipher.DECRYPT_MODE, privateKey, oaepParams);
        byte[] aesKeyBytes = cipher.doFinal(encryptedKeyBytes);
        System.out.println("[DEBUG] RSA 복호화 완료. AES 키 길이: " + aesKeyBytes.length);

        if (aesKeyBytes.length != 32) {
            throw new IOException("AES 키 길이가 32바이트가 아님: " + aesKeyBytes.length);
        }

        //원래 있던 envelopeKeyFile도 바이트로 저장 된거라 직렬화로 저장 되게 변경

        return new SecretKeySpec(aesKeyBytes, "AES");
    }


//    public SecretKey getAESKeyFromEnvelope(InputStream p_input, File envelopeKeyFile) throws Exception {
//
//		//개인키 파일 업로드
//		ObjectInputStream o_private = new ObjectInputStream(p_input);
//		PrivateKey privateKey = (PrivateKey)o_private.readObject();
//		o_private.close();
//        System.out.println("[DEBUG] 개인키 역직렬화 완료");
//
//        // 대칭키 복호화용 Cipher 초기화
//        Cipher cipher = Cipher.getInstance("RSA");
//        cipher.init(Cipher.DECRYPT_MODE, privateKey);
//
//
//        //FileInputStream으로 암호화 된 대칭키 읽어서 CipherInputStream으로 복호화
//        byte[] keyBytes = new byte[32]; // 대칭키(AES) 길이가 256비트(32byte)
//        try (
//            FileInputStream f_data = new FileInputStream(envelopeKeyFile);
//            CipherInputStream cis = new CipherInputStream(f_data, cipher);
//        ) {
//            int read = cis.read(keyBytes);
//            if (read != 32) {
//                throw new IOException("잘못된 대칭키 길이입니다.");
//            }
//        }
//        SecretKey secretKey = new SecretKeySpec(keyBytes, "AES"); //SecretKeySpec: byte 값이랑 + AES인거 매핑해서 SecretKey 객체로 전달
//
//        return secretKey;
//	}

}
