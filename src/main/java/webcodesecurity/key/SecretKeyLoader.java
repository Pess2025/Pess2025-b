package webcodesecurity.key;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.Serializable;
import java.security.Key;

public class SecretKeyLoader implements Serializable {
    private static final long serialVersionUID = 1L;
    public static Key loadKey(String fname, int keylength) {
        try (ObjectInputStream ois = new ObjectInputStream(new FileInputStream(fname))) {
            Key key = (Key) ois.readObject();

            return key;
        } catch (IOException | ClassNotFoundException e) {
            e.printStackTrace();
            return null;
        }
    }
}
