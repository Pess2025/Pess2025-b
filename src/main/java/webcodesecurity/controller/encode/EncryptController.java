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
import java.security.PublicKey;
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
            File outputDir = new File("output");
            if (!outputDir.exists()) outputDir.mkdirs();

            encryptedText.transferTo(new File("output/password.enc"));
            encryptedAesKey.transferTo(new File("output/aes_key_encrypted.bin"));

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
            System.out.println("🚀 /sign 진입");

            File keyFile = new File("output/aes_key_encrypted.bin");
            if (!keyFile.exists()) {
                System.err.println("❌ 암호화된 AES 키 없음");
                return ResponseEntity.status(500).body("암호화된 AES 키 없음");
            }

            System.out.println("🔑 개인키 로딩...");
            PrivateKey privateKey = (PrivateKey) SecretKeyLoader.loadKey("keys/private.key", 1024);
            System.out.println("✅ 개인키 로딩 완료");

            byte[] encryptedKeyBytes = Files.readAllBytes(keyFile.toPath());
            System.out.println("📦 암호화된 AES 키 로딩 완료");

            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            byte[] decryptedAesKey = cipher.doFinal(encryptedKeyBytes);
            System.out.println("🔓 AES 키 복호화 성공");

            Signature signature = Signature.getInstance("SHA256withRSA");
            signature.initSign(privateKey);
            signature.update(decryptedAesKey);
            byte[] sigBytes = signature.sign();
            System.out.println("✍ 서명 완료");

            Files.write(Paths.get("output/envelope.sig"), sigBytes);
            System.out.println("✔ envelope.sig 생성 완료");

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


    /*클라이언트에서 AES키를 서버 공개키로 암호화해야한다.
    * */
    @GetMapping("/public-key")
    public ResponseEntity<String> getPublicKey() {
        try {
            File publicKeyFile = new File(System.getProperty("user.dir") + "/keys/public.key");
            if (!publicKeyFile.exists()) {
                return ResponseEntity.status(404).body("공개키 파일이 존재하지 않습니다.");
            }

            byte[] bytes = java.nio.file.Files.readAllBytes(publicKeyFile.toPath());
            String encoded = java.util.Base64.getEncoder().encodeToString(bytes);  // ✅ 안전하게 문자열로 변환
            return ResponseEntity.ok(encoded);

        } catch (IOException e) {
            e.printStackTrace();
            return ResponseEntity.status(500).body("공개키 읽기 실패: " + e.getMessage());
        }
    }

    @PostMapping("/save-hash")
    public ResponseEntity<String> saveHash(@RequestParam("hashFile") MultipartFile hashFile) {
        try {
            String uploadPath = System.getProperty("user.dir") + File.separator + "output";
            File outputDir = new File(uploadPath);
            if (!outputDir.exists()) outputDir.mkdirs();

            File hashFilePath = new File(uploadPath, "hashed_password.txt");
            hashFile.transferTo(hashFilePath);

            return ResponseEntity.ok("해시 파일 저장 완료");
        } catch (IOException e) {
            e.printStackTrace();
            return ResponseEntity.status(500).body("해시 파일 저장 실패: " + e.getMessage());
        }
    }

}