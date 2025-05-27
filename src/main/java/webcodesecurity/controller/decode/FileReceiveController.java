package webcodesecurity.controller.decode;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;
import webcodesecurity.decode.EnvelopeDecode;
import webcodesecurity.decode.FilesDecode;
import webcodesecurity.decode.HashValidate;
import webcodesecurity.decode.PasswordMapManager;

import javax.crypto.SecretKey;
import java.io.FileInputStream;
import java.io.ObjectInputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.security.PublicKey;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/decode")
public class FileReceiveController {

    private final String UPLOAD_DIR = "uploads"; // 루트 밑에 uploads라는 폴더가 생기도록(파일 관리)

    @PostMapping("/upload")
    public ResponseEntity<String> handleFileUpload(
    		@RequestParam("encryptedFile") MultipartFile encryptedFile,
            @RequestParam("envelopeFile") MultipartFile envelopeFile,
            @RequestParam("privateKeyFile") MultipartFile privateKeyFile,
            @RequestParam("signatureFile") MultipartFile signatureFile,
            @RequestParam("publicKeyFile") MultipartFile publicKeyFile ) {

        try {
            // 업로드 폴더 없으면 생성
        	Path uploadPath = Path.of(UPLOAD_DIR);
            if (!Files.exists(uploadPath)) Files.createDirectories(uploadPath);

            Path encryptedPath = uploadPath.resolve("encrypted.dat");
            Path envelopePath = uploadPath.resolve("envelope.dat");
            Path privateKeyPath = uploadPath.resolve("private.key");
            Path signaturePath = uploadPath.resolve("signature.sig");
            Path publicKeyPath = uploadPath.resolve("public.key");

            Files.copy(encryptedFile.getInputStream(), encryptedPath, StandardCopyOption.REPLACE_EXISTING);
            Files.copy(envelopeFile.getInputStream(), envelopePath, StandardCopyOption.REPLACE_EXISTING);
            Files.copy(privateKeyFile.getInputStream(), privateKeyPath, StandardCopyOption.REPLACE_EXISTING);
            Files.copy(signatureFile.getInputStream(), signaturePath, StandardCopyOption.REPLACE_EXISTING);
            Files.copy(publicKeyFile.getInputStream(), publicKeyPath, StandardCopyOption.REPLACE_EXISTING);

            // 전자봉투 해독하여 AES 키 추출
            SecretKey aesKey = new EnvelopeDecode().getAESKeyFromEnvelope();

            // AES 키로 비밀번호 파일 복호화
            List<String> lines = new FilesDecode().decodeToLines(aesKey);
            String passwordText = String.join("\n", lines);

            // 해시 검증
            byte[] signatureBytes = Files.readAllBytes(signaturePath);
            ObjectInputStream o_public = new ObjectInputStream(new FileInputStream(publicKeyPath.toString()));
            PublicKey publicKey = (PublicKey)o_public.readObject();
            o_public.close();

            boolean valid = new HashValidate().validate(passwordText, signatureBytes, publicKey);
            if (!valid) return ResponseEntity.status(403).body("검증 실패: 위조된 파일입니다.");

            // Map 형태로 저장
            Map<String, String> pwMap = new PasswordMapManager().parse(lines);

            // 응답 반환
            return ResponseEntity.ok("검증 성공! 등록된 도메인 수: " + pwMap.size());
            
        } catch (Exception e) {
        	e.printStackTrace();
            return ResponseEntity.status(500).body("서버 오류: " + e.getMessage());
        }
    }

}
