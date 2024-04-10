package LoginApp;

import java.awt.BorderLayout;
import java.awt.GridLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Arrays;
import java.util.Base64;

import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JPasswordField;
import javax.swing.JTextField;

public class GUI implements ActionListener {
    
    private Connection connection;
    
    private JFrame frame;
    private JPanel panel;
    private JLabel userLabel;
    private JLabel passLabel;
    private JButton loginButton;
    private JButton registerButton;
    private JTextField usernameField;
    private JPasswordField passwordField;
    private JTextField registerUsernameField;
    private JPasswordField registerPasswordField;
    
    public GUI() {
        initializeGUI();
    }
    
    private void initializeGUI() {
        try {
            Class.forName("com.mysql.cj.jdbc.Driver");
            connection = DriverManager.getConnection(DBConfig.DB_URL, DBConfig.DB_USERNAME, DBConfig.DB_PASSWORD);
        } catch (Exception e) {
            System.out.println("Error connecting to the database: " + e.getMessage());
        }
        
        frame = new JFrame();
        panel = new JPanel();
        
        usernameField = new JTextField(20);
        userLabel = new JLabel("Username:");
        passwordField = new JPasswordField();
        passLabel = new JLabel("Password:");
        loginButton = new JButton("Login");
        loginButton.addActionListener(this);
        registerButton = new JButton("Register");
        registerButton.addActionListener(this);
        
        panel.setBorder(BorderFactory.createEmptyBorder(Constants.PANEL_BORDER_TOP, Constants.PANEL_BORDER_LEFT, Constants.PANEL_BORDER_BOTTOM, Constants.PANEL_BORDER_RIGHT));
        panel.setLayout(new GridLayout(0, 2));
        
        panel.add(userLabel);
        panel.add(usernameField);
        panel.add(passLabel);
        panel.add(passwordField);
        panel.add(loginButton);
        panel.add(registerButton);
        
        frame.add(panel, BorderLayout.CENTER);
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        frame.setTitle("TX");
        frame.setSize(Constants.WINDOW_WIDTH, Constants.WINDOW_HEIGHT);
        frame.setResizable(false);
        frame.setVisible(true);
    }
 
    @Override
    public void actionPerformed(ActionEvent e) {
        if (e.getSource() == loginButton) {
            performLogin();
        } else if (e.getSource() == registerButton) { 
            showRegisterWindow();
        }
    }

    private void performLogin() {
        String user = usernameField.getText().trim();
        char[] passChars = passwordField.getPassword();
        String pass = new String(passChars);
        
        try {
            byte[] passwordSalt = getSalt(user);
            if (passwordSalt != null) {
                PasswordUtils passwordUtils = new PasswordUtils();
                
                try {
                	
                    String hashedPassword = passwordUtils.hashPassword(pass, passwordSalt);
                    
                    try {
                        String query = "SELECT * FROM users WHERE username = ? AND password_hash = ?";
                        PreparedStatement statement = connection.prepareStatement(query);
                        statement.setString(1, user);
                        statement.setString(2, hashedPassword);
                        
                        ResultSet rs = statement.executeQuery();
                        
                        if (rs.next()) {
                            System.out.println("Successful login!");
                        } else {
                            System.out.println("Invalid credentials. Please try again.");
                        }
                        
                        rs.close();
                        statement.close();
                    } catch (SQLException ex) {
                        System.out.println("Error authenticating user: " + ex.getMessage());
                    } finally {
                        clearPassword(passChars);
                        Arrays.fill(passwordSalt, (byte) 0);
                    }
                } catch (NoSuchAlgorithmException ex) {
                    System.out.println("Error hashing password: " + ex.getMessage());
                }
            } else {
                System.out.println("User not found.");
            }
        } catch (SQLException ex) {
            System.out.println("Error getting salt: " + ex.getMessage());
        }
    }


    private void showRegisterWindow() {
        clearLoginForm();
        frame.remove(panel);
        
        JPanel registerPanel = new JPanel(new GridLayout(0, 2));
        registerPanel.setBorder(BorderFactory.createEmptyBorder(Constants.PANEL_BORDER_TOP, Constants.PANEL_BORDER_LEFT, Constants.PANEL_BORDER_BOTTOM, Constants.PANEL_BORDER_RIGHT));
        registerUsernameField = new JTextField();
        registerPasswordField = new JPasswordField();
        JButton confirmRegisterButton = new JButton("Register");
        JButton backButton = new JButton("Go Back");

        addComponentsToRegisterPanel(registerPanel, confirmRegisterButton, backButton);

        frame.add(registerPanel, BorderLayout.CENTER);
        frame.revalidate();
        frame.repaint();
        frame.setResizable(false);
    }

    private void addComponentsToRegisterPanel(JPanel registerPanel, JButton confirmRegisterButton, JButton backButton) {
        registerPanel.add(new JLabel("New User:"));
        registerPanel.add(registerUsernameField);
        registerPanel.add(new JLabel("New Password:"));
        registerPanel.add(registerPasswordField);
        registerPanel.add(confirmRegisterButton);
        registerPanel.add(backButton);
        
        confirmRegisterButton.addActionListener(e -> {
            String newUser = registerUsernameField.getText().trim();
            char[] passCharsNew = registerPasswordField.getPassword();
            
            try {
                PasswordUtils passwordUtils = new PasswordUtils();
                String password = String.valueOf(passCharsNew);
                
                byte[] saltArray = passwordUtils.generateSalt();
                String saltString = Base64.getEncoder().encodeToString(saltArray);
                String newPassword = passwordUtils.hashPassword(password, saltArray);
                
                try {
                    String query = "INSERT INTO users (username, password_hash, salt) VALUES (?, ?, ?)";
                    PreparedStatement statement = connection.prepareStatement(query);
                    statement.setString(1, newUser);
                    statement.setString(2, newPassword);
                    statement.setString(3, saltString);
                    
                    if (checkPasswordRequirements(passCharsNew) && isUsernameAvailable(newUser)) {
                        int lines = statement.executeUpdate();
                        
                        if (lines > 0) {
                            System.out.println("Account created successfully");
                            clearRegisterForm();
                            frame.remove(registerPanel);
                            frame.add(panel, BorderLayout.CENTER);
                            frame.revalidate();
                            frame.repaint();
                        } 
                    } else {
                        System.out.println("Your Password does not meet the minimum requirements or User is already taken");
                    }
                    
                    statement.close();
                } catch (SQLException ex) {
                    System.out.println("Error while registering user: " + ex.getMessage());
                } finally {
                    clearPassword(passCharsNew);
                    Arrays.fill(saltArray, (byte) 0);
                }
            } catch (NoSuchAlgorithmException ex) {
                System.out.println("Error: " + ex.getMessage());
            }
        });

        backButton.addActionListener(e -> {
            clearRegisterForm();
            frame.remove(registerPanel);
            frame.add(panel, BorderLayout.CENTER);
            frame.revalidate();
            frame.repaint();
        });
    }

    private void clearRegisterForm() {
        registerUsernameField.setText("");
        registerPasswordField.setText("");
    }
    
    private void clearLoginForm() {
        usernameField.setText("");
        passwordField.setText("");
    }

    private void clearPassword(char[] passChars) {
        Arrays.fill(passChars, ' ');
    }
    
    private boolean checkPasswordRequirements(char[] passChars) {
        int minimumLength = 10;
        boolean hasUppercase = false;
        boolean hasDigit = false;
        boolean hasSpecialChar = false;
        
        if (passChars.length < minimumLength) {
            return false;
        }
        
        for (char c : passChars) {
            if (Character.isUpperCase(c)) {
                hasUppercase = true;
            }
            else if (Character.isDigit(c)) {
                hasDigit = true;
            }
            else if (!Character.isLetterOrDigit(c)) {
                hasSpecialChar = true;
            }
        }
        return hasUppercase && hasDigit && hasSpecialChar;
    }
    
    private boolean isUsernameAvailable(String username) {
        boolean isAvailable = false;
        try {
            String checkQuery = "SELECT COUNT(*) FROM users WHERE username = ?";
            PreparedStatement checkStatement = connection.prepareStatement(checkQuery);
            checkStatement.setString(1, username);
            ResultSet result = checkStatement.executeQuery();
            
            if (result.next() && result.getInt(1) == 0) {
                isAvailable = true;
            }
            
            checkStatement.close();
            result.close();
        } catch (SQLException ex) {
            System.out.println("Error while checking username availability: " + ex.getMessage());
        }
        return isAvailable;
    }
    
    private byte[] getSalt(String username) throws SQLException {
        byte[] salt = null;
        String query = "SELECT salt FROM users WHERE username = ?";
        
        try (PreparedStatement statement = connection.prepareStatement(query)) {
            statement.setString(1, username);
            
            try (ResultSet rs = statement.executeQuery()) {
                if (rs.next()) {
                    String saltBase64 = rs.getString("salt");
                    salt = Base64.getDecoder().decode(saltBase64);
                }
            }
        }
        
        return salt;
    }

}
