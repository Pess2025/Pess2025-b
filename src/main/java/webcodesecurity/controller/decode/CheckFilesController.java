package webcodesecurity.controller.decode;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.io.File;
import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/decode")
public class CheckFilesController {

    @GetMapping("/check-files")
    public ResponseEntity<Map<String, Boolean>> checkRequiredFiles() {
        Map<String, Boolean> fileStatus = new HashMap<>();
        fileStatus.put("password.txt", new File("output/password.enc").exists());
        fileStatus.put("password_hash.txt", new File("output/password_hash.txt").exists());
        fileStatus.put("envelope.key", new File("output/envelope.sig").exists());
        fileStatus.put("public.key", new File("output/en_public.key").exists());

        return ResponseEntity.ok(fileStatus);
    }
}

