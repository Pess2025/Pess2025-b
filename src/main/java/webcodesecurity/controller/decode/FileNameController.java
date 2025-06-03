package webcodesecurity.controller.decode;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.io.File;
import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/result")
public class FileNameController {
    @GetMapping("/filename")
    public ResponseEntity<Map<String, String>> useFilename() {
        File txtFile = new File("output/password.txt");

        Map<String, String> fileStatus = new HashMap<>();
        fileStatus.put("file", txtFile.getName());

        return ResponseEntity.ok(fileStatus);
    }

}
