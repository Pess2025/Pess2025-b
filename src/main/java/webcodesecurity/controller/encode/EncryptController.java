package webcodesecurity.controller.encode;

import jakarta.annotation.Resource;
import org.springframework.core.io.InputStreamResource;

import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;
import webcodesecurity.key.SecretKeyLoader;

import javax.crypto.Cipher;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.PrivateKey;
import java.security.Signature;

@RestController
@RequestMapping("/api/encrypt")
public class EncryptController {

    /**
     * 클라이언트에서 암호화된 파일과 평문 AES 키를 전달하면,
     * AES 키에 전자서명을 생성하고 저장함.
     */
    @PostMapping("/envelope")
    public ResponseEntity<String> uploadEncryptedData(
            @RequestParam("encryptedText") MultipartFile encryptedText,
            @RequestParam("encryptedAesKey") MultipartFile encryptedAesKey
    ) {
        try {
            // 현재 클래스 기준 상대경로 → 절대경로로 설정
            String basePath = new File(".").getCanonicalPath(); // = 프로젝트 루트
            File outputDir = new File(basePath, "output");

            if (!outputDir.exists()) outputDir.mkdirs();

            File encryptedFile = new File(outputDir, "password.enc");
            File aesKeyFile = new File(outputDir, "aes_key_encrypted.bin");

            encryptedText.transferTo(encryptedFile);
            encryptedAesKey.transferTo(aesKeyFile);

            System.out.println("📁 암호문 저장 위치: " + encryptedFile.getAbsolutePath());
            System.out.println("📁 AES 키 저장 위치: " + aesKeyFile.getAbsolutePath());

            return ResponseEntity.ok("AES 암호문 및 키 저장 완료");

        } catch (IOException e) {
            e.printStackTrace();
            return ResponseEntity.status(500).body("파일 저장 실패: " + e.getMessage());
        }
    }

    /**
     * 저장된 AES 키에 대해 전자서명을 생성
    */

    @PostMapping("/sign")
    public ResponseEntity<String> generateSignature() {
        try {
            File keyFile = new File("output/aes_key_encrypted.bin");
            if (!keyFile.exists()) {
                return ResponseEntity.status(500).body("암호화된 AES 키 없음");
            }

            // 개인키 로드
            PrivateKey privateKey = (PrivateKey) SecretKeyLoader.loadKey("keys/private.key", 2048);

            // 암호화된 AES 키 파일 읽기 (그 자체에 서명할 것!)
            byte[] encryptedKeyBytes = Files.readAllBytes(keyFile.toPath());

            // 전자서명 생성
            Signature signature = Signature.getInstance("SHA256withRSA");
            signature.initSign(privateKey);
            signature.update(encryptedKeyBytes);  // 🔄 복호화 없이, 암호화된 키 자체를 서명
            byte[] sigBytes = signature.sign();
            System.out.println("✍ 서명 완료");

            // 파일로 저장
            try (ObjectOutputStream oos = new ObjectOutputStream(
                    new FileOutputStream("output/envelope.sig"))) {
                oos.writeObject(sigBytes); // 직렬화된 byte[]
                System.out.println("✔ envelope.sig 직렬화 저장 완료");
            }

            return ResponseEntity.ok("전자서명 생성 완료");
        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.status(500).body("전자서명 실패: " + e.getMessage());
        }
    }

    /**
     * 암호문 다운로드
     */
    @GetMapping("/encrypted-file")
    public ResponseEntity<Resource> downloadEncryptedFile() throws IOException {
        File file = new File("output/password.enc");
        InputStreamResource resource = new InputStreamResource(new FileInputStream(file));

        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"password.enc\"")
                .contentLength(file.length())
                .contentType(MediaType.APPLICATION_OCTET_STREAM)
                .body((Resource) resource);
    }

    /**
     * 전자서명 파일 다운로드
     */
    @GetMapping("/envelope")
    public ResponseEntity<Resource> downloadEnvelopeFile() throws IOException {
        File file = new File("output/envelope.sig");
        InputStreamResource resource = new InputStreamResource(new FileInputStream(file));

        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"envelope.sig\"")
                .contentLength(file.length())
                .contentType(MediaType.APPLICATION_OCTET_STREAM)
                .body((Resource) resource);
    }

    /**
     * 암호문 + 서명을 ZIP으로 압축하여 제공
     */
    @GetMapping("/download-bundle")
    public ResponseEntity<InputStreamResource> downloadEncryptedBundle() throws IOException {
        File enc = new File("output/password.enc");
        File sig = new File("output/envelope.sig");
        File zip = File.createTempFile("bundle-", ".zip");

        try (FileOutputStream fos = new FileOutputStream(zip);
             java.util.zip.ZipOutputStream zos = new java.util.zip.ZipOutputStream(fos)) {
            addToZip(zos, enc, "password.enc");
            addToZip(zos, sig, "envelope.sig");
        }

        InputStreamResource resource = new InputStreamResource(new FileInputStream(zip));
        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"encrypted-bundle.zip\"")
                .contentLength(zip.length())
                .contentType(MediaType.APPLICATION_OCTET_STREAM)
                .body(resource);
    }

    private void addToZip(java.util.zip.ZipOutputStream zos, File file, String entryName) throws IOException {
        zos.putNextEntry(new java.util.zip.ZipEntry(entryName));
        try (FileInputStream fis = new FileInputStream(file)) {
            byte[] buffer = new byte[1024];
            int len;
            while ((len = fis.read(buffer)) != -1) {
                zos.write(buffer, 0, len);
            }
        }
        zos.closeEntry();
    }

    @PostMapping("/save-hash")
    public ResponseEntity<String> saveHash(@RequestParam("hashFile") MultipartFile hashFile) {
        try {
            if (hashFile == null || hashFile.isEmpty()) {
                return ResponseEntity.badRequest().body("📛 업로드된 파일이 null 또는 비어 있음");
            }

            String outputPath = System.getProperty("user.dir") + File.separator + "output";
            System.out.println("📂 outputPath: " + outputPath);

            File outputDir = new File(outputPath);
            if (!outputDir.exists() && !outputDir.mkdirs()) {
                return ResponseEntity.status(500).body("디렉토리 생성 실패: " + outputPath);
            }

            File hashFilePath = new File(outputDir, "password_hash.txt");
            try (OutputStream os = new FileOutputStream(hashFilePath)) {
                os.write(hashFile.getBytes());
            }

            return ResponseEntity.ok("해시 파일 저장 완료: " + hashFilePath.getAbsolutePath());
        } catch (IOException e) {
            e.printStackTrace();
            return ResponseEntity.status(500).body("❌ 예외 발생: " + e.getMessage());
        }
    }

}
