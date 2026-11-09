package LoginApp;

import java.awt.BasicStroke;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.Font;
import java.awt.Graphics;
import java.awt.Graphics2D;
import java.awt.RenderingHints;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.util.Arrays;
import java.util.concurrent.ExecutionException;
import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.JButton;
import javax.swing.JComponent;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JPasswordField;
import javax.swing.JTextField;
import javax.swing.SwingWorker;
import javax.swing.plaf.basic.BasicButtonUI;

/** A small desktop shell around registration and login. */
public final class GUI {
    static final Font BODY_FONT = new Font(Font.SANS_SERIF, Font.PLAIN, 13);
    private static final Color NAVY = new Color(23, 39, 58);
    private static final Color INK = new Color(32, 48, 65);
    private static final Color MUTED = new Color(100, 113, 127);
    private static final Color GREEN = new Color(23, 112, 92);
    private static final Color BACKGROUND = new Color(248, 250, 252);
    private final AuthService auth;
    private final JPanel root = new JPanel(new BorderLayout());
    private final JPanel content = new JPanel(new BorderLayout());
    private final JTextField username = new JTextField();
    private final JPasswordField password = new JPasswordField();
    private final JPasswordField confirmation = new JPasswordField();
    private final JLabel status = new JLabel(" ");
    private JButton submit;
    private JButton switchMode;
    private JFrame frame;
    private boolean registering;
    private boolean ready;

    public GUI(AuthService auth, boolean local) {
        this.auth = auth;
        root.setPreferredSize(new Dimension(920, 700));
        root.add(sidebar(local), BorderLayout.WEST);
        content.setBackground(BACKGROUND);
        root.add(content, BorderLayout.CENTER);
        showForm();
        initializeDatabase();
    }

    public void show() {
        frame = new JFrame("File Cloud Transfer");
        frame.setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);
        frame.setContentPane(root);
        frame.setResizable(false);
        frame.pack();
        frame.setLocationRelativeTo(null);
        frame.addWindowListener(new WindowAdapter() {
            @Override public void windowClosed(WindowEvent event) {
                clearPasswords();
            }
        });
        updateDefaultButton();
        frame.setVisible(true);
        username.requestFocusInWindow();
    }

    JPanel view() {
        return root;
    }

    private JPanel sidebar(boolean local) {
        JPanel side = column(NAVY);
        side.setPreferredSize(new Dimension(310, 700));
        side.setBorder(BorderFactory.createEmptyBorder(40, 32, 32, 28));
        JLabel mark = label("FCT /", 20, Font.BOLD, new Color(117, 220, 191));
        side.add(mark);
        side.add(Box.createVerticalStrut(52));
        side.add(label("File Cloud", 30, Font.BOLD, Color.WHITE));
        side.add(label("Transfer", 30, Font.BOLD, Color.WHITE));
        side.add(Box.createVerticalStrut(20));
        side.add(label("<html>A desktop experiment in<br>account access and file sharing.</html>",
                14, Font.PLAIN, new Color(188, 202, 215)));
        side.add(Box.createVerticalStrut(30));
        JLabel mode = label(local ? "●  LOCAL DEMO" : "●  CUSTOM DATABASE", 11, Font.BOLD,
                new Color(117, 220, 191));
        mode.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(new Color(59, 87, 101)),
                BorderFactory.createEmptyBorder(9, 12, 9, 12)));
        side.add(mode);
        side.add(Box.createVerticalGlue());
        side.add(new TransferMark());
        side.add(Box.createVerticalStrut(24));
        side.add(label("EARLY PROTOTYPE", 10, Font.BOLD, new Color(117, 220, 191)));
        side.add(Box.createVerticalStrut(10));
        side.add(label("<html>Account access is ready.<br>File transfers are still to come.</html>",
                12, Font.PLAIN, new Color(188, 202, 215)));
        return side;
    }

    private void showForm() {
        clearPasswords();
        JPanel form = column(BACKGROUND);
        form.setBorder(BorderFactory.createEmptyBorder(30, 48, 24, 48));
        form.add(Box.createVerticalGlue());
        form.add(label(registering ? "CREATE AN ACCOUNT" : "ACCOUNT ACCESS", 10, Font.BOLD, GREEN));
        form.add(Box.createVerticalStrut(12));
        form.add(label(registering ? "Make yourself at home." : "Welcome back.", 27, Font.BOLD, INK));
        form.add(Box.createVerticalStrut(10));
        form.add(label(registering ? "Create an account to try the prototype." : "Sign in to your account to get started.",
                13, Font.PLAIN, MUTED));
        form.add(Box.createVerticalStrut(registering ? 16 : 30));
        addField(form, "Username", username);
        if (registering) {
            form.add(label("3–32 letters, numbers, dots, underscores or hyphens.", 10, Font.PLAIN, MUTED));
            form.add(Box.createVerticalStrut(12));
        }
        addField(form, "Password", password);
        if (registering) {
            form.add(label("Use 10–128 characters.", 10, Font.PLAIN, MUTED));
            form.add(Box.createVerticalStrut(12));
            addField(form, "Confirm password", confirmation);
        }
        status.setFont(BODY_FONT.deriveFont(12f));
        status.setAlignmentX(Component.LEFT_ALIGNMENT);
        status.setPreferredSize(new Dimension(400, 40));
        status.setMaximumSize(new Dimension(Integer.MAX_VALUE, 40));
        status.setText(" ");
        form.add(status);
        submit = button(registering ? "Create account" : "Sign in", true);
        submit.addActionListener(event -> {
            if (ready) authenticate();
            else initializeDatabase();
        });
        form.add(submit);
        form.add(Box.createVerticalStrut(12));
        switchMode = button(registering ? "Already registered? Sign in" : "New here? Create an account", false);
        switchMode.addActionListener(event -> {
            registering = !registering;
            showForm();
            username.requestFocusInWindow();
        });
        form.add(switchMode);
        form.add(Box.createVerticalGlue());
        replaceContent(form);
        updateDefaultButton();
    }

    private void initializeDatabase() {
        setBusy(true, "Connecting…");
        new SwingWorker<Void, Void>() {
            @Override protected Void doInBackground() throws Exception {
                auth.initialize();
                return null;
            }

            @Override protected void done() {
                try {
                    get();
                    ready = true;
                    message("Ready. Your accounts are saved in the selected database.", false);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    message("Connection interrupted. Please retry.", true);
                } catch (ExecutionException e) {
                    message("Could not connect. Check your database settings and retry.", true);
                } finally {
                    setBusy(false, null);
                }
            }
        }.execute();
    }

    private void authenticate() {
        String user = username.getText().trim();
        char[] secret = password.getPassword();
        char[] repeated = confirmation.getPassword();
        if (registering && !Arrays.equals(secret, repeated)) {
            Arrays.fill(secret, '\0');
            Arrays.fill(repeated, '\0');
            clearPasswords();
            message("The passwords do not match. Please try again.", true);
            password.requestFocusInWindow();
            return;
        }
        Arrays.fill(repeated, '\0');
        boolean creating = registering;
        setBusy(true, creating ? "Creating account…" : "Signing in…");
        new SwingWorker<Boolean, Void>() {
            @Override protected Boolean doInBackground() throws Exception {
                try {
                    if (creating) {
                        auth.register(user, secret);
                        return true;
                    }
                    return auth.login(user, secret);
                } finally {
                    Arrays.fill(secret, '\0');
                }
            }

            @Override protected void done() {
                clearPasswords();
                setBusy(false, null);
                try {
                    if (!get()) {
                        message("Invalid username or password. Please try again.", true);
                    } else if (creating) {
                        registering = false;
                        showForm();
                        message("Account created. You can now sign in.", false);
                        password.requestFocusInWindow();
                    } else {
                        showAccount(user);
                    }
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    message("Action interrupted. Please try again.", true);
                } catch (ExecutionException e) {
                    Throwable cause = e.getCause();
                    message(cause instanceof IllegalArgumentException ? cause.getMessage()
                            : "Could not reach the database. Please try again.", true);
                }
            }
        }.execute();
    }

    private void showAccount(String user) {
        JPanel account = column(BACKGROUND);
        account.setBorder(BorderFactory.createEmptyBorder(76, 48, 60, 48));
        account.add(label("CONNECTED", 10, Font.BOLD, GREEN));
        account.add(Box.createVerticalStrut(16));
        account.add(label("You're signed in.", 30, Font.BOLD, INK));
        account.add(Box.createVerticalStrut(14));
        account.add(label("Welcome, " + user + ".", 16, Font.PLAIN, INK));
        account.add(Box.createVerticalStrut(24));
        account.add(label("<html>Account access works. File uploads and cloud<br>connections are planned for a future version.</html>",
                13, Font.PLAIN, MUTED));
        account.add(Box.createVerticalStrut(36));
        account.add(planned("01", "File uploads"));
        account.add(Box.createVerticalStrut(12));
        account.add(planned("02", "Cloud connections"));
        account.add(Box.createVerticalGlue());
        JButton signOut = button("Sign out", true);
        signOut.addActionListener(event -> {
            username.setText("");
            showForm();
            username.requestFocusInWindow();
        });
        account.add(signOut);
        replaceContent(account);
        if (frame != null) frame.getRootPane().setDefaultButton(signOut);
    }

    private JPanel planned(String number, String title) {
        JPanel row = new JPanel(new BorderLayout(12, 0));
        row.setBackground(Color.WHITE);
        row.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(new Color(224, 230, 235)),
                BorderFactory.createEmptyBorder(17, 16, 17, 16)));
        row.add(label(number, 11, Font.BOLD, GREEN), BorderLayout.WEST);
        row.add(label(title, 13, Font.PLAIN, INK), BorderLayout.CENTER);
        row.add(label("Planned", 11, Font.PLAIN, MUTED), BorderLayout.EAST);
        row.setMaximumSize(new Dimension(Integer.MAX_VALUE, 56));
        row.setAlignmentX(Component.LEFT_ALIGNMENT);
        return row;
    }

    private void setBusy(boolean busy, String text) {
        submit.setEnabled(!busy);
        switchMode.setEnabled(!busy);
        username.setEnabled(!busy);
        password.setEnabled(!busy);
        confirmation.setEnabled(!busy);
        submit.setText(busy ? text : !ready ? "Retry connection" : registering ? "Create account" : "Sign in");
    }

    private void message(String text, boolean error) {
        status.setForeground(error ? new Color(169, 49, 57) : GREEN);
        status.setText("<html><body style='width:295px'>" + text + "</body></html>");
        status.getAccessibleContext().setAccessibleName(text);
    }

    private void clearPasswords() {
        password.setText("");
        confirmation.setText("");
    }

    private void replaceContent(JPanel panel) {
        content.removeAll();
        content.add(panel, BorderLayout.CENTER);
        content.revalidate();
        content.repaint();
    }

    private void updateDefaultButton() {
        if (frame != null) frame.getRootPane().setDefaultButton(submit);
    }

    private static JPanel column(Color background) {
        JPanel panel = new JPanel();
        panel.setLayout(new BoxLayout(panel, BoxLayout.Y_AXIS));
        panel.setBackground(background);
        return panel;
    }

    private static JLabel label(String text, int size, int style, Color color) {
        JLabel label = new JLabel(text);
        label.setFont(BODY_FONT.deriveFont(style, (float) size));
        label.setForeground(color);
        label.setAlignmentX(Component.LEFT_ALIGNMENT);
        return label;
    }

    private static void addField(JPanel panel, String title, JTextField field) {
        JLabel label = label(title, 12, Font.BOLD, INK);
        label.setLabelFor(field);
        panel.add(label);
        panel.add(Box.createVerticalStrut(8));
        field.setFont(BODY_FONT.deriveFont(15f));
        field.setForeground(INK);
        field.setBackground(Color.WHITE);
        field.setCaretColor(GREEN);
        field.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(new Color(208, 218, 226)),
                BorderFactory.createEmptyBorder(10, 12, 10, 12)));
        field.setMaximumSize(new Dimension(Integer.MAX_VALUE, 44));
        field.setPreferredSize(new Dimension(400, 44));
        field.setAlignmentX(Component.LEFT_ALIGNMENT);
        panel.add(field);
        panel.add(Box.createVerticalStrut(12));
    }

    private static JButton button(String text, boolean primary) {
        JButton button = new JButton(text);
        button.setUI(new BasicButtonUI());
        button.setFont(BODY_FONT.deriveFont(Font.BOLD));
        button.setBackground(primary ? GREEN : BACKGROUND);
        button.setForeground(primary ? Color.WHITE : GREEN);
        button.setOpaque(true);
        button.setContentAreaFilled(true);
        button.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(primary ? GREEN : new Color(213, 223, 229)),
                BorderFactory.createEmptyBorder(12, 14, 12, 14)));
        button.setMaximumSize(new Dimension(Integer.MAX_VALUE, 46));
        button.setAlignmentX(Component.LEFT_ALIGNMENT);
        return button;
    }

    private static final class TransferMark extends JComponent {
        TransferMark() {
            setPreferredSize(new Dimension(220, 70));
            setMaximumSize(new Dimension(220, 70));
            setAlignmentX(Component.LEFT_ALIGNMENT);
        }

        @Override protected void paintComponent(Graphics graphics) {
            Graphics2D g = (Graphics2D) graphics.create();
            g.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
            g.setStroke(new BasicStroke(2f));
            g.setColor(new Color(59, 87, 101));
            g.drawRoundRect(1, 12, 52, 45, 12, 12);
            g.drawRoundRect(165, 12, 52, 45, 12, 12);
            g.setColor(new Color(117, 220, 191));
            g.drawLine(73, 26, 144, 26);
            g.drawLine(136, 18, 144, 26);
            g.drawLine(136, 34, 144, 26);
            g.drawLine(73, 44, 144, 44);
            g.drawLine(73, 44, 81, 36);
            g.drawLine(73, 44, 81, 52);
            g.dispose();
        }
    }
}
