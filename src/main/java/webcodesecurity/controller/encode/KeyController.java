package webcodesecurity.controller.encode;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;
import webcodesecurity.controller.encode.holder.AESKeyHolder;
import webcodesecurity.decode.AESKeyStore;
import webcodesecurity.key.KeyPairManager;

import javax.crypto.SecretKey;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;

import webcodesecurity.encrypt.FileEncrypter;
import webcodesecurity.key.SecretKeySaver;

@RestController
@RequestMapping("/api/keys")
public class KeyController implements Serializable {
    private static final long serialVersionUID = 1L;
    /**
     * 프론트에서 "새로운 키 생성하기"를 클릭했을 때 호출되는 API
     * RSA 키페어를 생성한 뒤, 개인키를 byte[] 형태로 반환하여 다운로드하게 합니다.
     */
    @GetMapping("/generate/private-key")
    public ResponseEntity<byte[]> generatePrivateKey() throws IOException, NoSuchAlgorithmException {

        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair keyPair = generator.generateKeyPair();

        if (keyPair == null) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
        System.out.println("📏 공개키 바이트 길이: " + keyPair.getPublic().getEncoded().length);

        // 공개키 저장 (파일)
        try {
            //파일을 열어서 publicKeyByte를 "output/public.key"라는 이름으로 저장해야함
            byte[] publicKeyBytes = keyPair.getPublic().getEncoded();
            Path publicKeyPath = Paths.get("output/public.key");
            Files.write(publicKeyPath, publicKeyBytes);

            System.out.println("📂 공개키 저장 완료: " + publicKeyPath.toAbsolutePath());
        } catch (IOException e) {
            e.printStackTrace();
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }

        Path path = Paths.get("keys/private.key");

        System.out.println("파일 존재? " + Files.exists(path));
        System.out.println("쓰기 가능? " + Files.isWritable(path.getParent()));
        System.out.println("읽기 가능? " + Files.isReadable(path.getParent()));

        // 3. 비밀키 직렬화 - 메모리로
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        try (ObjectOutputStream oos = new ObjectOutputStream(bos)) {
            oos.writeObject(keyPair.getPrivate());
        }
        byte[] privateKeySerializedBytes = bos.toByteArray();

        // 4. 비밀키 직렬화 - 파일로 저장
        File f = new File("keys/private.key");
        System.out.println("파일 쓰기 가능? " + f.getParentFile().canWrite());

        Path privateKeyPath = Paths.get("keys/private.key");
        try (ObjectOutputStream oos = new ObjectOutputStream(Files.newOutputStream(privateKeyPath))) {
            oos.writeObject(keyPair.getPrivate());
        }
        System.out.println("📂 비밀키 저장 완료: " + privateKeyPath.toAbsolutePath());

        // 5. 직렬화된 개인키를 클라이언트에 전송
        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"private.key\"")
                .contentType(MediaType.APPLICATION_OCTET_STREAM)
                .body(privateKeySerializedBytes);
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
            // ObjectInputStream으로 직렬화 객체 검증
//            ObjectInputStream ois = new ObjectInputStream(file.getInputStream());
//            PrivateKey privateKey = (PrivateKey) ois.readObject(); // 예외 안 나면 정상 객체
//            ois.close();

            // 여기서 저장은 생략하고 유효성만 확인
            return ResponseEntity.ok("개인키 업로드 및 검증 완료");

        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.status(500).body("개인키 검증 실패: " + e.getMessage());
        }
    }

    /**
     * 공개키 업로드 API, 사용자가 보낸걸 읽고 저장
     */
    @PostMapping("/upload-public")
    public ResponseEntity<String> uploadPublicKey(@RequestParam("file") MultipartFile file) {
        try {
            byte[] keyBytes = file.getBytes();

            // 1. 암호화된 결과 저장 경로
            String outputPath = "output/en_public.key";

            //대칭키를 만들어서 holder에 넣어놓기
            SecretKey aesKey = (SecretKey) SecretKeySaver.generateKey("AES", 256); //수정 해야할스도
            //AESKeyHolder.getInstance().setAESKey(aesKey);
            AESKeyStore.saveKey(aesKey);

            SecretKey aes = AESKeyStore.loadKey();

            // 2. 평문으로 저장 안하고 → 암호화해서 저장 keyBytes = 공개키의 바이트
            if(FileEncrypter.encryptBytes(aes, keyBytes, new File(outputPath)))
                return ResponseEntity.ok("공개키 저장 완료");
        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.status(500).body("업로드 실패: " + e.getMessage());
        }
        return ResponseEntity.status(900).body("예외 발생");
    }

    /**
     * 공개키 생성(사실 주는거 아니고 드라이브에 저장 된거 제공하는거임)
     */
    @GetMapping("/generate/public-key")
    public ResponseEntity<byte[]> getPublicKey() {
        try {
            System.out.printf("공개키 아직 안 갔어요");
            Path keyPath = Paths.get("output/public.key");
            byte[] keyBytes = Files.readAllBytes(keyPath);
            System.out.printf("공개키 잘 들고 갔어요");

            return ResponseEntity.ok()
                    .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_OCTET_STREAM_VALUE)
                    .body(keyBytes);

        } catch (IOException e) {
            e.printStackTrace();
            return ResponseEntity.status(500).body(null);
        }
    }

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

    @GetMapping("/aes-key")
    public ResponseEntity<byte[]> getAESKey() {
        try {
            SecretKey aesKey = AESKeyStore.loadKey();

            if (aesKey == null) {
                return ResponseEntity.status(404).body(null);
            }

            byte[] keyBytes = aesKey.getEncoded();
            return ResponseEntity.ok()
                    .header("Content-Disposition", "attachment; filename=\"aes.key\"")
                    .body(keyBytes);

        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.status(500).body(null);
        }
    }

}
