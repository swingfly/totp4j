package test.java.com.johnson.totp;

import main.java.com.johnson.totp.TimeBasedOTP;
import org.junit.Before;
import org.junit.Test;

import static org.junit.Assert.*;

public class TimeBasedOTPTestCase {

    private TimeBasedOTP timeBasedOTP;

    @Before
    public void setUp() {
        timeBasedOTP = new TimeBasedOTP("HmacSHA1", 6, 10, 1);
    }

    @Test
    public void testGenerateTOTP() {
        String totp = timeBasedOTP.generateTOTP("test@aaaa.com");
        assertEquals(6, totp.length());
    }

    @Test
    public void testValidateTOTP() {
        String secret = "test@aaaa.com";
        String totp = timeBasedOTP.generateTOTP(secret);
        assertTrue(timeBasedOTP.validateTOTP(totp, secret.getBytes()));
    }

    @Test
    public void testValidateTOTP_window_true() throws InterruptedException {
        String secret = "test@aaaa.com";
        String totp = timeBasedOTP.generateTOTP(secret);
        Thread.sleep(5000);
        assertTrue(timeBasedOTP.validateTOTP(totp, secret.getBytes()));
    }

    @Test
    public void testValidateTOTP_window_false() throws InterruptedException {
        String secret = "test@aaaa.com";
        String totp = timeBasedOTP.generateTOTP(secret);
        Thread.sleep(25000);
        assertFalse(timeBasedOTP.validateTOTP(totp, secret.getBytes()));
    }

}
