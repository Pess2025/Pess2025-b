/**
 * 파일명 : EnvelopeGenerator.jsx
 * 설명 : 대칭키를 공개키로 암호화하여 전자봉투를 만듭니다.
 * 작성자 : 정여진
 * 작성일 : 2025.05.26.
 * */
package webcodesecurity.encrypt;

import webcodesecurity.key.SecretKeyLoader;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import java.io.FileOutputStream;
import java.security.PublicKey;

public class EnvelopeGenerator {

    /**
     * 전자봉투 파일을 생성하는 메서드입니다.
     *
     * secretKey 대칭키 (AES)
     * publicKeyFileName : 공개키가 저장된 파일 경로입니다.
     * envelopeOutputPath : 전자봉투를 저장할 파일 경로입니다.
     */
    public static void createEnvelopeFile(SecretKey secretKey, String publicKeyFileName, String envelopeOutputPath) throws Exception {
        // 1. 공개키 로딩
        PublicKey publicKey = (PublicKey) SecretKeyLoader.loadKey(publicKeyFileName, 1024);

        // 2. 대칭키를 byte[]로 추출
        byte[] symmetricKeyBytes = secretKey.getEncoded();

        // 3. 공개키로 대칭키를 암호화 (전자봉투 생성)
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encryptedKey = cipher.doFinal(symmetricKeyBytes);

        // 4. 전자봉투를 파일로 저장
        try (FileOutputStream fos = new FileOutputStream(envelopeOutputPath)) {
            fos.write(encryptedKey);
        }
    }
}