package webcodesecurity.decode;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.SecretKey;
import java.io.*;
import java.util.ArrayList;
import java.util.List;

public class FileDecode { //텍스트 파일 복호화하여 리스트로 전달

    public List<String> decodeToLines(SecretKey secretKey, File encryptedFile) throws Exception {

        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, secretKey);

        List<String> lines = new ArrayList<>();
        try (FileInputStream f_input = new FileInputStream(encryptedFile);
             CipherInputStream c_input = new CipherInputStream(f_input, cipher)
        ) {
            byte[] buffer = new byte[1024]; // 한 줄 최대 길이 제한
            int idx = 0; //현재 줄 길이

            int byteValue;
            while ((byteValue = c_input.read()) != -1) {
                if ((char) byteValue == '\n') { //줄 끝나서 버퍼 값을 리스트에 저장해야함
                    String line = new String(buffer, 0, idx, "UTF-8").trim(); //버퍼를 문자열로 변경
                    lines.add(line); //리스트에 해당 버퍼추가
                    idx = 0; // 다음 줄을 위해 초기화
                } else if ((char) byteValue != '\r') { //윈도우 줄바꿈이 \r\n이라 \r은 무시하고 그 외 값만 버퍼에 저장
                    if (idx < buffer.length) {
                    	buffer[idx++] = (byte) byteValue;
                    }
                }
            }
            // 마지막 줄이 \n 없이 끝났을 경우
            if (idx > 0) {
                String lastLine = new String(buffer, 0, idx, "UTF-8").trim(); //마지막 버퍼에 있는 내용도 리스트에 추가
                lines.add(lastLine);
            }
        }

        return lines;
    }
}
