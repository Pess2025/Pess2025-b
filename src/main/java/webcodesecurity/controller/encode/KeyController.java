/**
 * 프론트에서 키 생성 혹은 업로드 시 호출할 컨트롤러입니다.
 * */

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
import java.io.FileInputStream;
import java.io.IOException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import webcodesecurity.encrypt.FileEncrypter;

@RestController
@RequestMapping("/api/keys")
public class KeyController {

    /**
     * 프론트에서 "새로운 키 생성하기"를 클릭했을 때 호출되는 API
     *  RSA 키페어를 생성한 뒤, 개인키를 byte[] 형태로 반환하여 다운로드하게 합니다.
     * */
    @PostMapping("/generate")
    public ResponseEntity<byte[]> generatePrivateKey() {
        KeyPair keyPair = KeyPairManager.generateKeyPair("RSA", 1024);
        if (keyPair == null) {
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

    @PostMapping("/upload-public")
    public ResponseEntity<String> uploadPublicKey(@RequestParam("file") MultipartFile file) {
        try {
            String rootPath = System.getProperty("user.dir"); // 실행 경로
            File keyDir = new File(rootPath, "keys");
            if (!keyDir.exists()) keyDir.mkdirs();

            File destFile = new File(keyDir, "public.key");
            file.transferTo(destFile);

            return ResponseEntity.ok("공개키 저장 완료");
        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.status(500).body("업로드 실패: " + e.getMessage());
        }
    }


    @GetMapping("/public-key")
    public ResponseEntity<String> getPublicKey() {
        try {
            File publicKeyFile = new File(System.getProperty("user.dir") + "/keys/public.key");
            if (!publicKeyFile.exists()) {
                return ResponseEntity.status(404).body("공개키 파일이 존재하지 않습니다.");
            }

            // 여기서 length - 1 문제 발생.
            String content = java.nio.file.Files.readString(publicKeyFile.toPath());
            return ResponseEntity.ok(content);
        } catch (IOException e) {
            e.printStackTrace();
            return ResponseEntity.status(500).body("공개키 읽기 실패: " + e.getMessage());
        }
    }

}