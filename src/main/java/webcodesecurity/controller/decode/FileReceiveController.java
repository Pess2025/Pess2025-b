package webcodesecurity.controller.decode;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.File;
import java.io.IOException;

@RestController
@RequestMapping("/decode")
public class FileReceiveController {

    private final String uploadDir = "uploads"; // 루트 밑에 uploads라는 폴더가 생기도록(파일 관리)

    @PostMapping("/upload")
    public ResponseEntity<String> handleFileUpload(
            @RequestParam("encryptedFile") MultipartFile encryptedFile,
            @RequestParam("envelopeFile") MultipartFile envelopeFile,
            @RequestParam("privateKeyFile") MultipartFile privateKeyFile) {

        try {
            // 업로드 폴더 없으면 생성
            File dir = new File(uploadDir);
            if (!dir.exists()) dir.mkdirs();

            // 각 파일 저장
            saveFile(encryptedFile, "encrypted.dat");
            saveFile(envelopeFile, "envelope.dat");
            saveFile(privateKeyFile, "private.key");

            return ResponseEntity.ok("파일 업로드 성공");
        } catch (IOException e) {
            e.printStackTrace();
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("파일 업로드 실패");
        }
    }

    private void saveFile(MultipartFile file, String filename) throws IOException {
        File where = new File(uploadDir + File.separator + filename); //File.separator 윈도우는 /로, 맥이나 리눅스는 \로 보임
        file.transferTo(where); //파일 저장
    }
}
