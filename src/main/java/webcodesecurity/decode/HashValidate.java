package webcodesecurity.decode;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.SecretKey;
import java.io.File;
import java.io.FileInputStream;
import java.nio.file.Files;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.Signature;
import java.util.Arrays;

public class HashValidate { //기존에 저장 된 해시 파일과 텍스트 파일 값을
	
	//암호화된 해시 값(txt 형태로 저장)과 비밀번호 파일을 해시화 한 값을 비교 수정 필요 할 수도
    public boolean validate(SecretKey secretKey, File textFile, File exHashFile) throws Exception {

        //AESHolder에서 AES 키 받은게 secretKey, secretKey로 textFile 복호화 해야함

        byte[] expected = Files.readAllBytes(exHashFile.toPath()); //이전 해시 값
        //byte[] pwText = Files.readAllBytes(textFile.toPath()); // 암호화 된

        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, secretKey);

//        MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
//        messageDigest.update(pwText);
//        byte[] now = messageDigest.digest(); //새로 만든 해시 값

        try (
                FileInputStream f_input = new FileInputStream(textFile);
                CipherInputStream c_input = new CipherInputStream(f_input, cipher)
        ) {
            // 4. 해시 계산
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] buffer = new byte[1024];
            int bytesRead;
            while ((bytesRead = c_input.read(buffer)) != -1) {
                digest.update(buffer, 0, bytesRead);
            }

            byte[] now = digest.digest();

            return Arrays.equals(expected, now);
        }
    }
}