package webcodesecurity.decode;

import org.springframework.web.multipart.MultipartFile;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
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

        try {
            ObjectInputStream ois = new ObjectInputStream(file.getInputStream());
            PrivateKey privateKey = (PrivateKey) ois.readObject();
            ois.close();

            // 디렉터리 생성
            Path dir = Paths.get("keys");
            if (!Files.exists(dir)) {
                Files.createDirectories(dir);
            }

            // 기존 파일 삭제
            Path filePath = dir.resolve("private.key");
            try {
                Files.deleteIfExists(filePath); // 이 부분에서 예외가 발생하면 catch로 넘어감
            } catch (IOException e) {
                System.err.println("private.key 삭제 실패: " + e.getMessage());
            }

            // 파일 저장
            try (ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(filePath.toFile()))) {
                oos.writeObject(privateKey);
                System.out.println("private.key 저장 완료: " + filePath.toAbsolutePath());
            }


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


            return new SecretKeySpec(aesKeyBytes, "AES");
        } catch (Exception e) {
            System.err.println("복호화 실패: " + e.getMessage());
            throw new IllegalArgumentException("현재 PrivateKey는 암호화에 사용된 키가 아닙니다.");
        }
    }

}
