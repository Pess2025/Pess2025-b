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
        // 🔹 1. 저장된 해시 값 (hash.bin, raw 32 bytes)
        byte[] expected = Files.readAllBytes(exHashFile.toPath());

        // 🔹 2. 암호화된 텍스트 파일 (Base64 문자열)
        String base64Raw = new String(Files.readAllBytes(textFile.toPath()), StandardCharsets.UTF_8);
        if (base64Raw.startsWith("\uFEFF")) {
            base64Raw = base64Raw.substring(1); // BOM 제거
        }
        String base64 = base64Raw.replaceAll("\\s+", "");
        byte[] encryptedBytes = Base64.getDecoder().decode(base64);

        // 🔹 3. AES 복호화
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

            // 🔹 4. 복호화된 평문을 문자열로 변환하고 해시 계산
            byte[] decryptedBytes = plainOut.toByteArray();
            String decryptedText = new String(decryptedBytes, StandardCharsets.UTF_8);

            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hashInput = decryptedText.getBytes(StandardCharsets.UTF_8);  // 또는 그대로 decryptedBytes 사용 가능
            byte[] now = digest.digest(hashInput);

            // 🔍 디버깅 출력
            System.out.println("복호화된 평문 (UTF-8): " + decryptedText);
            System.out.println("복호화된 평문 (hex): " + bytesToHex(decryptedBytes));
            System.out.println("계산된 해시 (hex): " + bytesToHex(now));
            System.out.println("저장된 해시 (hex): " + bytesToHex(expected));

            return Arrays.equals(expected, now);
        }
        }}

/*
    // 기존에 저장 된 해시 파일과 복호화된 텍스트 파일 값을 비교
    public boolean validate(SecretKey secretKey, File textFile, File exHashFile) throws Exception {
        // 1. 저장된 해시 값 불러오기
        byte[] expected = Files.readAllBytes(exHashFile.toPath());

        // 2. 암호화된 파일(Base64 문자열로 저장된 AES 암호문) 읽기
        String base64Raw = new String(Files.readAllBytes(textFile.toPath()), StandardCharsets.UTF_8);

        // 3. BOM 제거 (있을 경우)
        if (base64Raw.startsWith("\uFEFF")) {
            base64Raw = base64Raw.substring(1);
        }

        // 4. 줄바꿈, 공백 제거
        String base64 = base64Raw.replaceAll("\\s+", "");

        // 5. Base64 디코딩 → AES 복호화 대상 바이트 배열
        byte[] encryptedBytes = Base64.getDecoder().decode(base64);

        // 6. AES 복호화 스트림 설정
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        try (
                ByteArrayInputStream bais = new ByteArrayInputStream(encryptedBytes);
                CipherInputStream c_input = new CipherInputStream(bais, cipher)
        ) {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");

            ByteArrayOutputStream plainOut = new ByteArrayOutputStream();
            byte[] buffer = new byte[1024];
            int bytesRead;

            while ((bytesRead = c_input.read(buffer)) != -1) {
                plainOut.write(buffer, 0, bytesRead);
                digest.update(buffer, 0, bytesRead); // 해시용
            }

            byte[] decryptedBytes = plainOut.toByteArray();
            byte[] now = digest.digest();

            // ✅ 복호화된 평문 로그 (텍스트로도 보기)
            System.out.println("복호화된 평문 (hex): " + bytesToHex(decryptedBytes));
            System.out.println("복호화된 평문 (UTF-8): " + new String(decryptedBytes, StandardCharsets.UTF_8));

            // ✅ 해시 로그
            System.out.println("계산된 해시: " + Base64.getEncoder().encodeToString(now));
            System.out.println("저장된 해시: " + Base64.getEncoder().encodeToString(expected));

            return Arrays.equals(expected, now);
        }
    }
}*/

            /*
            // 1. 저장된 해시 값 불러오기
            byte[] expected = Files.readAllBytes(exHashFile.toPath());

            // 2. 암호화된 파일(Base64 문자열로 저장된 AES 암호문) 읽기
            String base64Raw = new String(Files.readAllBytes(textFile.toPath()), StandardCharsets.UTF_8);

            // 3. BOM 제거 (있을 경우)
            if (base64Raw.startsWith("\uFEFF")) {
                base64Raw = base64Raw.substring(1);
            }

            // 4. 줄바꿈, 공백 제거
            String base64 = base64Raw.replaceAll("\\s+", "");

            // 5. Base64 디코딩 → AES 복호화 대상 바이트 배열
            byte[] encryptedBytes = Base64.getDecoder().decode(base64);

            // 6. AES 복호화 스트림 설정
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, secretKey);

            try (
                    ByteArrayInputStream bais = new ByteArrayInputStream(encryptedBytes);
                    CipherInputStream c_input = new CipherInputStream(bais, cipher)
            ) {
                MessageDigest digest = MessageDigest.getInstance("SHA-256");

                byte[] buffer = new byte[1024];
                int bytesRead;

                while ((bytesRead = c_input.read(buffer)) != -1) {
                    digest.update(buffer, 0, bytesRead);
                }

                byte[] now = digest.digest();

                // 디버깅용 로그 (선택)
                System.out.println("계산된 해시: " + Base64.getEncoder().encodeToString(now));
                System.out.println("저장된 해시: " + Base64.getEncoder().encodeToString(expected));

                return Arrays.equals(expected, now);
            }
        }
*/

/*
    //암호화된 해시 값(txt 형태로 저장)과 비밀번호 파일을 해시화 한 값을 비교 수정 필요 할 수도
    public boolean validate(SecretKey secretKey, File textFile, File exHashFile) throws Exception {

//        //secretKey로 textFile 복호화 해야하는데, Base64 문자열로 저장 되어 있어 이거 참고 해서 복호화 해주고 이걸 SHA-256으로 해시화 해줘
        byte[] expected = Files.readAllBytes(exHashFile.toPath()); // 저장된 해시값

// 1. Base64 복호화
//        String base64 = new String(Files.readAllBytes(textFile.toPath()), StandardCharsets.UTF_8).replaceAll("\\s+", "");
//        byte[] encryptedBytes = Base64.getDecoder().decode(base64);
        String base64Raw = new String(Files.readAllBytes(textFile.toPath()), StandardCharsets.UTF_8);
        if (base64Raw.startsWith("\uFEFF")) {
            base64Raw = base64Raw.substring(1); // BOM 제거
        }
        String base64 = base64Raw.replaceAll("\\s+", "");

// 2. 복호화 + 해시 계산
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, secretKey);

        try (
                ByteArrayInputStream bais = new ByteArrayInputStream(base64);
                CipherInputStream c_input = new CipherInputStream(bais, cipher)
        ) {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");

            byte[] buffer = new byte[1024];
            int bytesRead;
            while ((bytesRead = c_input.read(buffer)) != -1) {
                digest.update(buffer, 0, bytesRead);
            }

            byte[] now = digest.digest();
            return Arrays.equals(expected, now);
//        }
//        byte[] expected = Files.readAllBytes(exHashFile.toPath()); // 저장된 해시값
//        byte[] salt = Files.readAllBytes(saltFile.toPath()); // salt도 별도 파일로 전달받음
//
//        String base64 = new String(Files.readAllBytes(textFile.toPath()), StandardCharsets.UTF_8).replaceAll("\\s+", "");
//        byte[] encryptedBytes = Base64.getDecoder().decode(base64);
//
//        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
//        cipher.init(Cipher.DECRYPT_MODE, secretKey);
//
//        try (
//                ByteArrayInputStream bais = new ByteArrayInputStream(encryptedBytes);
//                CipherInputStream c_input = new CipherInputStream(bais, cipher)
//        ) {
//            MessageDigest digest = MessageDigest.getInstance("SHA-256");
//
//            // 먼저 salt 업데이트
//            digest.update(salt);
//
//            // 복호화된 평문 파일을 읽으며 해시
//            byte[] buffer = new byte[1024];
//            int bytesRead;
//            while ((bytesRead = c_input.read(buffer)) != -1) {
//                digest.update(buffer, 0, bytesRead);
//            }
//
//            byte[] now = digest.digest();
//            return Arrays.equals(expected, now);
//        }

        }
    }
    */
