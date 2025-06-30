package webcodesecurity.decode;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.SecretKey;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.Signature;
import java.util.Arrays;
import java.util.Base64;

public class HashValidate { //기존에 저장 된 해시 파일과 텍스트 파일 값을

    private String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02X ", b));
        }
        return sb.toString().trim();
    }
    public boolean validate(SecretKey secretKey, File textFile, File exHashFile) throws Exception {
        //저장된 해시 값 (hash.bin, raw 32 bytes)
        byte[] expected = Files.readAllBytes(exHashFile.toPath());

        // 암호화된 텍스트 파일 (Base64 문자열)
        String base64Raw = new String(Files.readAllBytes(textFile.toPath()), StandardCharsets.UTF_8);
        if (base64Raw.startsWith("\uFEFF")) {
            base64Raw = base64Raw.substring(1); // BOM 제거
        }
        String base64 = base64Raw.replaceAll("\\s+", "");
        byte[] encryptedBytes = Base64.getDecoder().decode(base64);

        // AES 복호화
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, secretKey);

        try (
                ByteArrayInputStream bais = new ByteArrayInputStream(encryptedBytes);
                CipherInputStream c_input = new CipherInputStream(bais, cipher);
                ByteArrayOutputStream plainOut = new ByteArrayOutputStream()
        ) {
            byte[] buffer = new byte[1024];
            int bytesRead;
            while ((bytesRead = c_input.read(buffer)) != -1) {
                plainOut.write(buffer, 0, bytesRead);
            }

            // 복호화된 평문을 문자열로 변환하고 해시 계산
            byte[] decryptedBytes = plainOut.toByteArray();
            String decryptedText = new String(decryptedBytes, StandardCharsets.UTF_8);

            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hashInput = decryptedText.getBytes(StandardCharsets.UTF_8);
            byte[] now = digest.digest(hashInput);

            // 디버깅 출력
            System.out.println("복호화된 평문 (UTF-8): " + decryptedText);
            System.out.println("복호화된 평문 (hex): " + bytesToHex(decryptedBytes));
            System.out.println("계산된 해시 (hex): " + bytesToHex(now));
            System.out.println("저장된 해시 (hex): " + bytesToHex(expected));

            return Arrays.equals(expected, now);
        }
        }}
