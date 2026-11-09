package LoginApp;

import java.awt.GraphicsEnvironment;
import javax.swing.SwingUtilities;
import javax.swing.UIManager;

public final class Main {
    private Main() { }

    public static void main(String[] args) {
        if (GraphicsEnvironment.isHeadless()) {
            System.err.println("File Cloud Transfer needs a desktop to display its Swing window.");
            System.exit(1);
        }
        SwingUtilities.invokeLater(() -> {
            UIManager.put("Button.font", GUI.BODY_FONT);
            UIManager.put("Label.font", GUI.BODY_FONT);
            UIManager.put("TextField.font", GUI.BODY_FONT);
            UIManager.put("PasswordField.font", GUI.BODY_FONT);
            DBConfig database = DBConfig.fromEnvironment();
            new GUI(new AuthService(database), database.isLocal()).show();
        });
    }
}
