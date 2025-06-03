package webcodesecurity.controller.decode;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import webcodesecurity.decode.FileDecode;
import webcodesecurity.controller.decode.holder.AESKeyHolder;
import webcodesecurity.controller.decode.holder.PasswordMapHolder;
import webcodesecurity.decode.PasswordMapManager;

import java.io.File;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/decode")
public class DecryptController {

    @PostMapping("/password-file")
    public ResponseEntity<String> decryptPasswordFile() {
        try {
            File txtFile = new File("output/password.txt");
            List<String> lines = new FileDecode().decodeToLines(AESKeyHolder.getInstance().getAESKey(), txtFile);

            Map<String, String> passwordMap = new PasswordMapManager().parse(lines);
            PasswordMapHolder.getInstance().setPasswordMap(passwordMap);

            return ResponseEntity.ok("비밀번호 파일 복호화 및 Map 저장 성공");
        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.status(500).body("복호화 실패: " + e.getMessage());
        }
    }
}
