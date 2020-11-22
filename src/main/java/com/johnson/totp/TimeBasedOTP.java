package main.java.com.johnson.totp;

import java.util.Calendar;
import java.util.GregorianCalendar;
import java.util.TimeZone;

public class TimeBasedOTP extends HmacOTP {

    public static final int DEFAULT_INTERVAL_SECONDS = 30;
    public static final int DEFAULT_DELAY_WINDOW = 1;

    private Clock clock;

    public TimeBasedOTP() {
        this(DEFAULT_ALGORITHM, DEFAULT_NUMBER_DIGITS, DEFAULT_INTERVAL_SECONDS, DEFAULT_DELAY_WINDOW);
    }

    /**
     * @param algorithm the encryption algorithm
     * @param numberDigits the number of digits for tokens
     * @param timeIntervalInSeconds the number of seconds a token is valid
     * @param lookAheadWindow the number of previous intervals that should be used to validate tokens.
     */
    public TimeBasedOTP(String algorithm, int numberDigits, int timeIntervalInSeconds, int lookAheadWindow) {
        super(numberDigits, algorithm, lookAheadWindow);
        this.clock = new Clock(timeIntervalInSeconds);
    }

    /**
     * <p>Generates a token.</p>
     *
     * @param secretKey the secret key to derive the token from.
     */
    public String generateTOTP(String secretKey) {
        long T = this.clock.getCurrentInterval();

        String steps = Long.toHexString(T).toUpperCase();

        // Just get a 16 digit string
        while (steps.length() < 16)
            steps = "0" + steps;

        return generateOTP(secretKey, steps, this.numberDigits, this.algorithm);
    }

    /**
     * <p>Validates a token using a secret key.</p>
     *
     * @param token  OTP string to validate
     * @param secret Shared secret
     * @return
     */
    public boolean validateTOTP(String token, byte[] secret) {
        long currentInterval = this.clock.getCurrentInterval();

        for (int i = this.lookAheadWindow; i >= 0; --i) {
            String steps = Long.toHexString(currentInterval - i).toUpperCase();

            // Just get a 16 digit string
            while (steps.length() < 16)
                steps = "0" + steps;

            String candidate = generateOTP(new String(secret), steps, this.numberDigits, this.algorithm);

            if (candidate.equals(token)) {
                return true;
            }
        }

        return false;
    }

    public void setCalendar(Calendar calendar) {
        this.clock.setCalendar(calendar);
    }

    private static class Clock {

        private final int interval;
        private Calendar calendar;

        public Clock(int interval) {
            this.interval = interval;
        }

        public long getCurrentInterval() {
            Calendar currentCalendar = this.calendar;

            if (currentCalendar == null) {
                currentCalendar = GregorianCalendar.getInstance(TimeZone.getTimeZone("UTC"));
            }

            return (currentCalendar.getTimeInMillis() / 1000) / this.interval;
        }

        public void setCalendar(Calendar calendar) {
            this.calendar = calendar;
        }
    }
}
