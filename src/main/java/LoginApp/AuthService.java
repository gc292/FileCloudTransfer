package LoginApp;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.regex.Pattern;

/** Authentication logic kept separate from Swing so it can be tested without a desktop. */
public final class AuthService {
    private static final Pattern USERNAME = Pattern.compile("[A-Za-z0-9_.-]{3,32}");
    private final DBConfig database;

    public AuthService(DBConfig database) {
        this.database = database;
    }

    public void initialize() throws SQLException {
        try (Connection connection = database.connect();
             PreparedStatement statement = connection.prepareStatement("""
                     CREATE TABLE IF NOT EXISTS fct_users (
                         username VARCHAR(32) PRIMARY KEY,
                         password_hash VARCHAR(255) NOT NULL
                     )
                     """)) {
            statement.executeUpdate();
        }
    }

    public void register(String username, char[] password) throws SQLException {
        validate(username, password);
        String hash = PasswordUtils.hash(password);
        try (Connection connection = database.connect();
             PreparedStatement statement = connection.prepareStatement(
                     "INSERT INTO fct_users (username, password_hash) VALUES (?, ?)")) {
            statement.setString(1, username);
            statement.setString(2, hash);
            statement.executeUpdate();
        } catch (SQLException e) {
            if ("23505".equals(e.getSQLState()) || e.getErrorCode() == 1062) {
                throw new IllegalArgumentException("That username is already taken.");
            }
            throw e;
        }
    }

    public boolean login(String username, char[] password) throws SQLException {
        if (!USERNAME.matcher(username).matches() || password.length == 0 || password.length > 128) {
            return false;
        }
        try (Connection connection = database.connect();
             PreparedStatement statement = connection.prepareStatement(
                     "SELECT password_hash FROM fct_users WHERE username = ?")) {
            statement.setString(1, username);
            try (ResultSet result = statement.executeQuery()) {
                return result.next() && PasswordUtils.verify(password, result.getString(1));
            }
        }
    }

    private static void validate(String username, char[] password) {
        if (!USERNAME.matcher(username).matches()) {
            throw new IllegalArgumentException("Use 3–32 letters, numbers, dots, underscores or hyphens.");
        }
        if (password.length < 10 || password.length > 128) {
            throw new IllegalArgumentException("Choose a password with 10–128 characters.");
        }
    }
}
