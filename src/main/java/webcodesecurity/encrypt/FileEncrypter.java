/**
 * 파일명 : FileEncrypter.jsx
 * 설명 : 파일을 AES로 암호화합니다.
 * 작성자 : 정여진
 * 작성일 : 2025.05.26.
 * */
package webcodesecurity.encrypt;

import webcodesecurity.controller.encode.holder.AESKeyHolder;
import webcodesecurity.decode.AESKeyStore;
import webcodesecurity.key.SecretKeySaver;

import javax.crypto.*;
import java.io.*;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

public class FileEncrypter {

    public static SecretKey encryptFile(String inputFilePath, String outputFilePath) throws Exception {

        System.out.println("FileEncrypter.encryptFile 호출됨");
        System.out.println("평문 파일: " + inputFilePath);
        System.out.println("암호문 저장 경로: " + new File(outputFilePath).getAbsolutePath());

        //AES 대칭키 생성
        SecretKey secretKey = AESKeyStore.loadKey();

        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);

        //파일 읽고 암호화 후 저장
        try (FileInputStream fis = new FileInputStream(inputFilePath);
             FileOutputStream fos = new FileOutputStream(outputFilePath)) {

            byte[] buffer = new byte[1024];
            int bytesRead;

            while ((bytesRead = fis.read(buffer)) != -1) {
                byte[] output = cipher.update(buffer, 0, bytesRead);
                if (output != null) fos.write(output);
            }

            byte[] finalBytes = cipher.doFinal();
            if (finalBytes != null) fos.write(finalBytes);

            Arrays.fill(buffer, (byte) 0); // 메모리 덤프를 막기 위해 평문 메모리는 지워야한다.0으로

        } catch (FileNotFoundException e) {
            throw new RuntimeException(e);
        } catch (IOException e) {
            throw new RuntimeException(e);
        } catch (IllegalBlockSizeException e) {
            throw new RuntimeException(e);
        } catch (BadPaddingException e) {
            throw new RuntimeException(e);
        }

        return secretKey;
    }

    public static boolean encryptBytes(SecretKey aes, byte[] input, File outputFile) throws Exception {

        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, aes);


        try (FileOutputStream fos = new FileOutputStream(outputFile)) {
            byte[] encrypted = cipher.doFinal(input);
            fos.write(encrypted);
            return true; // 정상 처리 완료 시
        } catch (Exception e) {
            e.printStackTrace();
            return false;         // 예외 발생 시 false 반환
        }

    }

}
