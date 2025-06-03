package webcodesecurity.decode;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class PasswordMapManager {

    public Map<String, String> parse(List<String> lines) { 
        Map<String, String> passwordMap = new HashMap<>();

        for (String line : lines) {
            int spaceIndex = line.indexOf(' '); //공백의 위치 찾기 -> 도메인이랑 pw 사이에 있는지 확인을 위함
            if (spaceIndex > 0 && spaceIndex < line.length() - 1) { //spaceIndex가 0이면 도메인이 비어있는 거, spaceIndex가 line.length() - 1이면 pw가 비어있는 거
                String domain = line.substring(0, spaceIndex).trim(); //앞이 도메인
                String password = line.substring(spaceIndex + 1).trim(); //뒤가 pw
                passwordMap.put(domain, password); //map에 저장
            }
            else if(spaceIndex == 0){
                System.out.println("서비스 명이 비어있습니다.");
            } else if(spaceIndex == line.length() - 1){
                System.out.println("비밀번호가 비어있습니다.");
            }
            else{
                System.out.println("MapManager 예외 상황입니다.");
            }
        }

        return passwordMap;
    }
}
