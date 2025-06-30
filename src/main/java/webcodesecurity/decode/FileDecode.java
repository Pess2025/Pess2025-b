package webcodesecurity.decode;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.SecretKey;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

public class FileDecode { //텍스트 파일 복호화하여 리스트로 전달 -> Map 사용을 위함

    public List<String> decodeToLines(SecretKey secretKey, File encryptedFile) throws Exception {

        if (secretKey == null) {
            throw new IllegalArgumentException("AES 키가 null입니다.");
        }

        byte[] keyBytes = secretKey.getEncoded();
        System.out.println("AES 키 길이: " + keyBytes.length); // 16, 24, 32 중 하나여야 함

        System.out.print("AES 키 (hex): ");
        for (byte b : keyBytes) {
            System.out.printf("%02X ", b);
        }
        System.out.println();

        // 암호문 파일 읽기
        String base64;
        try (BufferedReader reader = new BufferedReader(
                new InputStreamReader(new FileInputStream(encryptedFile), StandardCharsets.UTF_8))) {
            base64 = reader.lines().reduce("", String::concat).trim();
        }

        // 프론트에서 암호화해서 Base64로 디코드 해야함 (암호화 된 바이트 배열)
        byte[] encryptedBytes = Base64.getDecoder().decode(base64);

        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        System.out.println("암호문 길이(byte): " + encryptedBytes.length);
        if (encryptedBytes.length % 16 != 0) {
            System.out.println("암호문 길이가 16의 배수가 아닙니다!");
        }
        byte[] decrypted = cipher.doFinal(encryptedBytes);

        // 복호화된 결과를 줄 단위로 split
        List<String> lines = new ArrayList<>();
        try (BufferedReader lineReader = new BufferedReader(
                new InputStreamReader(new ByteArrayInputStream(decrypted), StandardCharsets.UTF_8))) {
            String line;
            while ((line = lineReader.readLine()) != null) {
                lines.add(line.trim());
            }
        }

        return lines;
    }

}
