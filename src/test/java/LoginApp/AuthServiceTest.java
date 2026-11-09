package LoginApp;

import static org.junit.jupiter.api.Assertions.*;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.Statement;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class AuthServiceTest {
    @TempDir Path directory;
    private DBConfig database;
    private AuthService auth;

    @BeforeEach void setUp() throws Exception {
        database = new DBConfig("jdbc:h2:file:" + directory.resolve("accounts"), "sa", "");
        auth = new AuthService(database);
        auth.initialize();
    }

    @Test void accountSurvivesNewServiceAndSchemaInitialization() throws Exception {
        auth.register("demo.user", "A long passphrase 🌍".toCharArray());
        AuthService reopened = new AuthService(database);
        reopened.initialize();
        assertTrue(reopened.login("demo.user", "A long passphrase 🌍".toCharArray()));
        assertFalse(reopened.login("demo.user", "incorrect password".toCharArray()));
        assertFalse(reopened.login("unknown", "A long passphrase 🌍".toCharArray()));
    }

    @Test void duplicateCannotReplaceExistingAccount() throws Exception {
        auth.register("demo", "first password".toCharArray());
        IllegalArgumentException error = assertThrows(IllegalArgumentException.class,
                () -> auth.register("demo", "second password".toCharArray()));
        assertEquals("That username is already taken.", error.getMessage());
        assertTrue(auth.login("demo", "first password".toCharArray()));
        assertFalse(auth.login("demo", "second password".toCharArray()));
    }

    @Test void rejectsInvalidInputBeforeWritingAccounts() throws Exception {
        for (String name : new String[]{"", "ab", "x".repeat(33), "has space", "' OR 1=1 --"}) {
            assertThrows(IllegalArgumentException.class,
                    () -> auth.register(name, "long enough password".toCharArray()));
        }
        for (String secret : new String[]{"", "123456789", "a".repeat(129)}) {
            assertThrows(IllegalArgumentException.class,
                    () -> auth.register("valid.user", secret.toCharArray()));
        }
        assertFalse(auth.login("' OR 1=1 --", "long enough password".toCharArray()));
        assertFalse(auth.login("valid.user", new char[0]));
        try (Connection connection = database.connect(); Statement query = connection.createStatement();
             ResultSet result = query.executeQuery("SELECT COUNT(*) FROM fct_users")) {
            assertTrue(result.next());
            assertEquals(0, result.getInt(1));
        }
    }

    @Test void storesSaltedHashesInsteadOfPlaintext() throws Exception {
        auth.register("first", "same password".toCharArray());
        auth.register("second", "same password".toCharArray());
        try (Connection connection = database.connect(); Statement query = connection.createStatement();
             ResultSet result = query.executeQuery("SELECT password_hash FROM fct_users ORDER BY username")) {
            assertTrue(result.next());
            String first = result.getString(1);
            assertTrue(first.startsWith("pbkdf2-sha256$600000$"));
            assertFalse(first.contains("same password"));
            assertTrue(result.next());
            assertNotEquals(first, result.getString(1));
        }
    }
}
