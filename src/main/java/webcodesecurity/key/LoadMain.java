package webcodesecurity.key;

import java.security.Key;
import java.util.Scanner;

public class LoadMain {

    public static void main(String[] args) {
        Scanner sc = new Scanner(System.in);
        // 공개키
        System.out.println("공개키를 저장한 파일 이름: ");
        String publicKeyFileName = sc.next();

        Key publicKey = SecretKeyLoader.loadKey(publicKeyFileName, 2048); // 문제에서 고정.

        System.out.println("암호화 알고리즘:" + publicKey.getAlgorithm());
        System.out.println("복구된 공개키 정보: ");
        System.out.println("키의 길이(bytes): " + publicKey.getEncoded().length);

        byte[] publicKeyEncoded = publicKey.getEncoded();
        for (byte b : publicKeyEncoded) {
            System.out.printf("%02X ", b);
        }
        System.out.println();

        // 개인키
        System.out.println("개인키를 저장한 파일 이름: ");
        String privateKeyFileName = sc.next();

        Key privateKey = SecretKeyLoader.loadKey(privateKeyFileName, 1024);

        System.out.println("암호화 알고리즘: " + privateKey.getAlgorithm());
        System.out.println("복구된 개인키 정보: ");
        System.out.println("키의 길이 (bytes): " + privateKey.getEncoded().length);

        byte[] privateKeyEncoded = privateKey.getEncoded();
        for (byte b : privateKeyEncoded) {
            System.out.printf("%02X ", b);
        }
        System.out.println();

        System.out.println("출력이 완료되었습니다.");
        sc.close();
    }

}
