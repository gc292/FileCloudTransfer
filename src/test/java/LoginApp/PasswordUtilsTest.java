package LoginApp;

import static org.junit.jupiter.api.Assertions.*;
import org.junit.jupiter.api.Test;

class PasswordUtilsTest {
    @Test void verifiesCorrectPasswordAndRejectsChanges() {
        String hash = PasswordUtils.hash("a long password".toCharArray());
        assertTrue(PasswordUtils.verify("a long password".toCharArray(), hash));
        assertFalse(PasswordUtils.verify("a Long password".toCharArray(), hash));
    }

    @Test void malformedHashesFailWithoutCrashingOrExcessiveWork() {
        for (String hash : new String[]{"", "sha256$hash", "pbkdf2-sha256$oops$x$x",
                "pbkdf2-sha256$2147483647$x$x", "pbkdf2-sha256$600000$%%%$%%%",
                "pbkdf2-sha256$600000$YWJj$YWJj"}) {
            assertFalse(PasswordUtils.verify("a long password".toCharArray(), hash));
        }
        assertFalse(PasswordUtils.verify("a long password".toCharArray(), null));
    }
}
