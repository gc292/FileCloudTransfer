package LoginApp;

import static org.junit.jupiter.api.Assertions.*;
import java.awt.Component;
import java.awt.Container;
import java.awt.Graphics2D;
import java.awt.RenderingHints;
import java.awt.image.BufferedImage;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.BooleanSupplier;
import javax.imageio.ImageIO;
import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JTextField;
import javax.swing.SwingUtilities;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class GUITest {
    @TempDir Path directory;

    @Test void registrationLoginAndSignOutWorkFromTheInterface() throws Exception {
        DBConfig database = new DBConfig("jdbc:h2:file:" + directory.resolve("ui"), "sa", "");
        AtomicReference<GUI> reference = new AtomicReference<>();
        SwingUtilities.invokeAndWait(() -> reference.set(new GUI(new AuthService(database), true)));
        JPanel view = reference.get().view();
        await(() -> button(view, "Sign in") != null && button(view, "Sign in").isEnabled());
        capture(view, "login");
        SwingUtilities.invokeAndWait(() -> {
            button(view, "New here? Create an account").doClick();
            field(view, "Username").setText("demo.user");
            field(view, "Password").setText("a long password");
            field(view, "Confirm password").setText("different password");
            button(view, "Create account").doClick();
            assertTrue(hasText(view, "The passwords do not match"));
            assertEquals("", field(view, "Password").getText());
        });
        capture(view, "register");
        SwingUtilities.invokeAndWait(() -> {
            field(view, "Password").setText("a long password");
            field(view, "Confirm password").setText("a long password");
            button(view, "Create account").doClick();
        });
        await(() -> hasText(view, "Account created."));
        SwingUtilities.invokeAndWait(() -> {
            field(view, "Password").setText("wrong password");
            button(view, "Sign in").doClick();
        });
        await(() -> hasText(view, "Invalid username or password"));
        SwingUtilities.invokeAndWait(() -> {
            field(view, "Password").setText("a long password");
            button(view, "Sign in").doClick();
        });
        await(() -> hasText(view, "You're signed in."));
        capture(view, "account");
        SwingUtilities.invokeAndWait(() -> {
            assertTrue(hasText(view, "Welcome, demo.user."));
            button(view, "Sign out").doClick();
            assertEquals("", field(view, "Username").getText());
            assertEquals("", field(view, "Password").getText());
            assertNotNull(button(view, "Sign in"));
        });
    }

    @Test void unavailableDatabaseOffersRetryInsteadOfBrokenLogin() throws Exception {
        AtomicReference<GUI> reference = new AtomicReference<>();
        DBConfig invalid = new DBConfig("jdbc:unsupported:test", "", "");
        SwingUtilities.invokeAndWait(() -> reference.set(new GUI(new AuthService(invalid), false)));
        JPanel view = reference.get().view();
        await(() -> hasText(view, "Could not connect."));
        SwingUtilities.invokeAndWait(() -> {
            assertTrue(button(view, "Retry connection").isEnabled());
            button(view, "Retry connection").doClick();
        });
        await(() -> button(view, "Retry connection") != null && button(view, "Retry connection").isEnabled());
    }

    private static void await(BooleanSupplier condition) throws Exception {
        assertTimeoutPreemptively(Duration.ofSeconds(20), () -> {
            AtomicBoolean done = new AtomicBoolean();
            while (!done.get()) {
                SwingUtilities.invokeAndWait(() -> done.set(condition.getAsBoolean()));
                if (!done.get()) Thread.sleep(20);
            }
        });
    }

    private static JButton button(Container view, String text) {
        return components(view).stream().filter(JButton.class::isInstance).map(JButton.class::cast)
                .filter(button -> button.getText().equals(text)).findFirst().orElse(null);
    }

    private static JTextField field(Container view, String label) {
        return components(view).stream().filter(JLabel.class::isInstance).map(JLabel.class::cast)
                .filter(item -> item.getText().equals(label)).map(JLabel::getLabelFor)
                .map(JTextField.class::cast).findFirst().orElseThrow();
    }

    private static boolean hasText(Container view, String text) {
        return components(view).stream().filter(JLabel.class::isInstance).map(JLabel.class::cast)
                .anyMatch(label -> label.getText().contains(text));
    }

    private static List<Component> components(Container parent) {
        List<Component> result = new ArrayList<>();
        for (Component component : parent.getComponents()) {
            result.add(component);
            if (component instanceof Container container) result.addAll(components(container));
        }
        return result;
    }

    /** Render the actual Swing view for the README, without requiring a display server. */
    private static void capture(JPanel view, String name) throws Exception {
        String output = System.getProperty("fct.previewDir");
        if (output == null) return;
        Path destination = Path.of(output);
        Files.createDirectories(destination);
        SwingUtilities.invokeAndWait(() -> {
            view.setSize(view.getPreferredSize());
            layout(view);
            BufferedImage image = new BufferedImage(view.getWidth() * 2, view.getHeight() * 2,
                    BufferedImage.TYPE_INT_RGB);
            Graphics2D graphics = image.createGraphics();
            graphics.scale(2, 2);
            graphics.setRenderingHint(RenderingHints.KEY_TEXT_ANTIALIASING, RenderingHints.VALUE_TEXT_ANTIALIAS_ON);
            view.printAll(graphics);
            graphics.dispose();
            try {
                ImageIO.write(image, "png", destination.resolve(name + ".png").toFile());
            } catch (java.io.IOException e) {
                throw new java.io.UncheckedIOException(e);
            }
        });
    }

    private static void layout(Container container) {
        container.doLayout();
        for (Component component : container.getComponents()) {
            if (component instanceof Container child) layout(child);
        }
    }
}
