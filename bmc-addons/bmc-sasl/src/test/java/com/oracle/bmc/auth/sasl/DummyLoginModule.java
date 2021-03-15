package com.oracle.bmc.auth.sasl;


import com.oracle.bmc.auth.BasicAuthenticationDetailsProvider;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.UUID;

public class DummyLoginModule extends OciLoginModule {

    @Override
    protected BasicAuthenticationDetailsProvider loadAuthenticationProvider(
        Map<String, ?> options) {

        String key = "-----BEGIN RSA PRIVATE KEY-----\n"
            + "MIIEogIBAAKCAQEAo6L8nZ04JotiwZhiMA0kemutG2HROJ4rJlEYyAbIMyULffLa\n"
            + "KXljlASyYA+0/9Yf9a+Ij+zMapogUwA+z/0389xeDfqvfVrUE5Hd3fEUGnOUTfIf\n"
            + "OCjDWv0UlGl4KxlZIZgqoRUHK6IQDbDVodl5uNnzo67/ZwQu11s=\n"
            + "-----END RSA PRIVATE KEY-----";

        return new BasicAuthenticationDetailsProvider() {

            private final String dummyId = UUID.randomUUID().toString();

            @Override
            public String getKeyId() {
                return dummyId;
            }

            @Override
            public InputStream getPrivateKey() {
                return new ByteArrayInputStream(key.getBytes(StandardCharsets.UTF_8));
            }

            @Override
            public String getPassPhrase() {
                return dummyId;
            }

            @Override
            public char[] getPassphraseCharacters() {
                return new char[0];
            }
        };
    }
}
