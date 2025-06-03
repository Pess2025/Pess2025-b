package webcodesecurity.controller.encode;

import jakarta.annotation.Resource;
import org.springframework.core.io.InputStreamResource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;
import webcodesecurity.key.KeyPairManager;

import javax.crypto.SecretKey;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.util.Base64;

import webcodesecurity.encrypt.FileEncrypter;

@RestController
@RequestMapping("/api/keys")
public class KeyController {

    /**
     * 프론트에서 "새로운 키 생성하기"를 클릭했을 때 호출되는 API
     * RSA 키페어를 생성한 뒤, 개인키를 byte[] 형태로 반환하여 다운로드하게 합니다.
     */
    @PostMapping("/generate")
    public ResponseEntity<byte[]> generatePrivateKey() {
        KeyPair keyPair = KeyPairManager.generateKeyPair("RSA", 1024);
        if (keyPair == null) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }

        // 공개키 저장 (파일)
        try {
            Path publicKeyPath = Paths.get("output/public.key");
            Files.createDirectories(publicKeyPath.getParent()); // 폴더 없으면 생성
            Files.write(publicKeyPath, keyPair.getPublic().getEncoded());
        } catch (IOException e) {
            e.printStackTrace();
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }

        byte[] privateKeyBytes = keyPair.getPrivate().getEncoded();
        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"private.key\"")
                .body(privateKeyBytes);
    }

    /**
     * 사용자가 기존 개인키 파일을 업로드할 때 호출되는 API입니다.
     * 파일 내용을 바이트 배열로 읽고, RSA 알고리즘 기반의 개인키로 복원 가능한지 검증만 수행합니다.
     *
     * @param file 업로드된 개인키 파일 (.key)
     * @return 복원 성공 여부에 따라 응답 문자열 반환
     */
    @PostMapping("/upload")
    public ResponseEntity<String> uploadPrivateKey(@RequestParam("file") MultipartFile file) {
        try {
            byte[] keyBytes = file.getBytes();

            // 1. 암호화된 결과 저장 경로
            String outputPath = "output/private.key.enc";

            // 2. 평문으로 저장 안하고 → 암호화해서 저장
            SecretKey aesKey = FileEncrypter.encryptBytes(keyBytes, new File(outputPath));

            // 3. 평문 키 저장 안함! 전자봉투도 지금은 생성 안 함

            return ResponseEntity.ok("개인키 업로드 및 암호화 완료");
        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.status(500).body("암호화 실패: " + e.getMessage());
        }
    }

    /**
     * 공개키 업로드 API
     */
    @PostMapping("/upload-public")
    public ResponseEntity<String> uploadPublicKey(@RequestParam("file") MultipartFile file) {
        try {
            String rootPath = System.getProperty("user.dir"); // 실행 경로
            File keyDir = new File(rootPath, "keys");
            if (!keyDir.exists()) keyDir.mkdirs();

            File destFile = new File(keyDir, "public.key"); //아마 사용자에게 주는 공개키
            file.transferTo(destFile);

            return ResponseEntity.ok("공개키 저장 완료");
        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.status(500).body("업로드 실패: " + e.getMessage());
        }
    }

    /**
     * 공개키 읽기 API
     */
//    @GetMapping("/public-key")
//    public ResponseEntity<String> getPublicKey() {
//        try {
//            // 저장된 공개키 바이너리 불러오기
//            Path keyPath = Paths.get("src/main/java/webcodesecurity/output/public.key");
//            byte[] keyBytes = Files.readAllBytes(keyPath);
//
//            // Base64로 인코딩 (줄바꿈 포함)
//            String base64 = Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(keyBytes);
//
//            // PEM 문자열 포맷
//            String pem = "-----BEGIN PUBLIC KEY-----\n" + base64 + "\n-----END PUBLIC KEY-----";
//
//            return ResponseEntity.ok()
//                    .header(HttpHeaders.CONTENT_TYPE, MediaType.TEXT_PLAIN_VALUE)
//                    .body(pem);
//        } catch (IOException e) {
//            e.printStackTrace();
//            return ResponseEntity.status(500).body(null);
//        }
//    }

    /**
     * base64 문자열을 일정 길이마다 줄바꿈 처리
     */
    private String insertLineBreaks(String base64, int length) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < base64.length(); i += length) {
            sb.append(base64, i, Math.min(i + length, base64.length())).append("\n");
        }
        return sb.toString();
    }

    @GetMapping("/public-key-binary")
    public ResponseEntity<byte[]> getPublicKeyBinary() throws IOException {
        try {
            System.out.println("✅ [DEBUG] public-key-binary 진입");
            
            // 실행 경로 확인
            String rootPath = System.getProperty("user.dir");
            System.out.println("[DEBUG] 현재 실행 경로: " + rootPath);

            Path keyPath = Paths.get(rootPath, "output", "public.key");
            System.out.println("[DEBUG] 공개키 예상 경로: " + keyPath.toAbsolutePath());

            if (!Files.exists(keyPath)) {
                System.err.println("[ERROR] 공개키 파일이 존재하지 않습니다.");
                return ResponseEntity.status(404).body(null);
            }

            Path keyPath1 = Paths.get("output/public.key");
            byte[] keyBytes = Files.readAllBytes(keyPath1);

            return ResponseEntity.ok()
                    .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=public.key")
                    .contentType(MediaType.APPLICATION_OCTET_STREAM)
                    .body(keyBytes);
        } catch (IOException e) {
            e.printStackTrace();
            return ResponseEntity.status(500).body(null);
        }
    }

}
