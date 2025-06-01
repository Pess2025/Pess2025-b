package webcodesecurity.controller.decode.holder;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class PasswordMapHolder {
    private static final PasswordMapHolder instance = new PasswordMapHolder();
    private Map<String, String> passwordMap = new ConcurrentHashMap<>();

    private PasswordMapHolder() {}

    public static PasswordMapHolder getInstance() {
        return instance;
    }

    public void setPasswordMap(Map<String, String> map) {
        this.passwordMap = map;
    }

    public Map<String, String> getPasswordMap() {
        return passwordMap;
    }
}
