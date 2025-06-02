package webcodesecurity.key;

import webcodesecurity.encrypt.EnvelopeGenerator;
import webcodesecurity.encrypt.FileEncrypter;
import webcodesecurity.encrypt.SecretKeyGenerator;

import javax.crypto.SecretKey;
import java.io.File;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;
import java.util.Scanner;

public class SaveMain {

    public static void main(String[] args) throws Exception {
        Scanner sc = new Scanner(System.in);

        // 1. RSA 키 쌍 생성
        KeyPair keypair = KeyPairManager.generateKeyPair("RSA", 2048);
        PublicKey publicKey = keypair.getPublic();
        PrivateKey privateKey = keypair.getPrivate();

        // 2. 콘솔 출력
        System.out.println("📌 공개키 알고리즘: " + publicKey.getAlgorithm());
        System.out.println("📌 공개키 길이 (bytes): " + publicKey.getEncoded().length);
        System.out.println("📌 개인키 알고리즘: " + privateKey.getAlgorithm());

        // 3. 저장 경로 입력
        System.out.print("공개키 PEM 저장 경로 (예: output/public.pem): ");
        String publicPemFile = sc.nextLine().trim();
        System.out.print("공개키 BIN 저장 경로 (예: output/public.key.bin): ");
        String publicBinFile = sc.nextLine().trim();
        System.out.print("개인키 BIN 저장 경로 (예: output/private.key.bin): ");
        String privateBinFile = sc.nextLine().trim();

        // 4. PEM 저장
        savePublicKeyAsPem(publicPemFile, publicKey);

        // 5. byte[] 바이너리 저장
        Files.write(Paths.get(publicBinFile), publicKey.getEncoded());
        Files.write(Paths.get(privateBinFile), privateKey.getEncoded());

        System.out.println("✅ PEM 및 BIN 키 파일 저장 완료");

        // 6. AES 키 생성
        SecretKey aesKey = SecretKeyGenerator.generateAESKey(256);
        System.out.println("✅ AES 대칭키 생성 완료");

        // 7. 전자봉투 생성 (AES 대칭키를 RSA 공개키로 암호화)
        EnvelopeGenerator.createEnvelopeFile(aesKey, publicPemFile, "output/encrypted-key.sig");
        System.out.println("✅ 전자봉투(encrypted-key.sig) 생성 완료");

        // 8. 공개키 바이트를 대칭키로 암호화 → 저장
        FileEncrypter.encryptBytes(publicKey.getEncoded(), new File("output/encrypted-public.pem"));
        System.out.println("✅ 공개키 암호화(encrypted-public.pem) 저장 완료");
    }

    // 공개키를 PEM으로 저장
    private static void savePublicKeyAsPem(String filePath, PublicKey publicKey) throws Exception {
        byte[] encoded = publicKey.getEncoded(); // X.509 (SPKI)
        String base64 = Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(encoded);

        String pem = "-----BEGIN PUBLIC KEY-----\n" + base64 + "\n-----END PUBLIC KEY-----";
        Files.writeString(Paths.get(filePath), pem);

        System.out.println("✅ 공개키 PEM 저장 완료: " + filePath);
    }
}
