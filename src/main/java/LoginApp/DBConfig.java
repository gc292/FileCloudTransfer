package LoginApp;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;

/** Connection settings. The default database needs no separate server. */
public record DBConfig(String url, String username, String password) {
    public static DBConfig fromEnvironment() {
        return new DBConfig(
                setting("FCT_DB_URL", "jdbc:h2:file:./data/filecloudtransfer"),
                setting("FCT_DB_USER", "sa"),
                setting("FCT_DB_PASSWORD", ""));
    }

    private static String setting(String name, String fallback) {
        String value = System.getenv(name);
        return value == null ? fallback : value;
    }

    public Connection connect() throws SQLException {
        return DriverManager.getConnection(url, username, password);
    }

    public boolean isLocal() {
        return url.startsWith("jdbc:h2:file:");
    }
}
