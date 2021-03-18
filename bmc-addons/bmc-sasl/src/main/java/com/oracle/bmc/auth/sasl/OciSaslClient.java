/**
 * Copyright (c) 2016, 2021, Oracle and/or its affiliates.  All rights reserved. This software is
 * dual-licensed to you under the Universal Permissive License (UPL) 1.0 as shown at
 * https://oss.oracle.com/licenses/upl or Apache License 2.0 as shown at
 * http://www.apache.org/licenses/LICENSE-2.0. You may choose either license.
 */
package com.oracle.bmc.auth.sasl;

import com.google.common.base.Preconditions;
import com.google.protobuf.ByteString;
import com.google.protobuf.InvalidProtocolBufferException;
import com.oracle.bmc.auth.BasicAuthenticationDetailsProvider;
import com.oracle.bmc.auth.RefreshableOnNotAuthenticatedProvider;
import com.oracle.bmc.http.signing.internal.PEMFileRSAPrivateKeySupplier;
import com.oracle.bmc.http.signing.internal.SignatureSigner;
import com.oracle.bmc.identity.auth.sasl.messages.OciSaslMessages.Challenge;
import com.oracle.bmc.identity.auth.sasl.messages.OciSaslMessages.Key;
import com.oracle.bmc.identity.auth.sasl.messages.OciSaslMessages.Response;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.interfaces.RSAPrivateKey;
import java.time.OffsetDateTime;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.sasl.SaslClient;
import javax.security.sasl.SaslClientFactory;
import javax.security.sasl.SaslException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

/**
 * Implementation of a {@link SaslClient} for the OCI SASL mechanism. That class shouldn't be
 * instanciated manually but registered using the {@link OciSaslClientProvider} and calling {@link
 * javax.security.sasl.Sasl#createSaslClient(String[], String, String, String, Map,
 * CallbackHandler)} using the proper mechanism.
 */
@Slf4j
public class OciSaslClient implements SaslClient {

    public static final int MIN_CHALLENGE_SIZE = 32;
    public static final int MAX_CHALLENGE_SIZE = 256;

    private static final SignatureSigner SIGNER = new SignatureSigner();

    private final OciMechanism mechanism;
    private final BasicAuthenticationDetailsProvider authProvider;
    private final String intent;

    private OciPrivateKey currentPrivateKey = null;

    private State state = State.KEY_ID;

    private enum State {
        KEY_ID,
        SIGNING,
        COMPLETE
    }

    private OciSaslClient(
        OciMechanism mechanism,
        BasicAuthenticationDetailsProvider authProvider,
        String intent) {
        this.mechanism = mechanism;
        this.authProvider = authProvider;
        this.intent = intent;
        if (authProvider != null) {
            LOG.info("in constructor - auth provider is NOT null! mechanism {}, intent {}", mechanism,
                intent);
        } else {
            LOG.info("in constructor - auth provider is null! mechanism {}, intent {}",
                mechanism, intent);
        }
    }

    @Override
    public String getMechanismName() {
        return mechanism.mechanismName();
    }

    @Override
    public byte[] evaluateChallenge(byte[] challenge) throws SaslException {
        switch (state) {
            case KEY_ID:
                // First step is to send the keyId with the intent
                state = State.SIGNING;
                return generateKeyMessage().toByteArray();
            case SIGNING:
                // Response should now contain the challenge sent by the server that we have to sign
                Response response = signChallenge(challenge);
                state = State.COMPLETE;
                return response.toByteArray();
            default:
                return new byte[0];
        }
    }

    private Key generateKeyMessage() {
        // Because the authProvider might be used across multiple clients,
        // we need to protect its access while we generate and retrieve a new private key
        if (authProvider == null) {
            LOG.info("generateKeyMessage - auth provider is null!");
        } else {
            LOG.info("generateKeyMessage - auth provider is Not Null!");
        }
        synchronized (authProvider) {
            // Get a new token for each new key exchange to prevent stale keys
            if (authProvider instanceof RefreshableOnNotAuthenticatedProvider) {
                ((RefreshableOnNotAuthenticatedProvider) authProvider).refresh();
            }

            currentPrivateKey =
                new OciPrivateKey(
                    authProvider.getKeyId(),
                    authProvider.getPrivateKey(),
                    authProvider.getPassphraseCharacters());

            return Key.newBuilder().setKeyId(currentPrivateKey.keyId).setIntent(intent).build();
        }
    }

    private Response signChallenge(byte[] serializedChallenge) throws SaslException {

        Preconditions.checkArgument(currentPrivateKey != null);

        final Challenge challenge = getAndValidateChallenge(serializedChallenge);
        final long epoch = OffsetDateTime.now().toEpochSecond();

        final PEMFileRSAPrivateKeySupplier keySupplier =
            new PEMFileRSAPrivateKeySupplier(
                currentPrivateKey.privateKey, currentPrivateKey.passphraseCharacters);

        currentPrivateKey = null;

        final RSAPrivateKey privateKey =
            keySupplier
                .getKey()
                .toJavaUtil()
                .orElseThrow(() -> new SaslException("Unable to get private key"));

        final byte[] intentBytes = intent.getBytes(StandardCharsets.UTF_8);

        final int messageToSignLength =
            challenge.getChallenge().toByteArray().length + intentBytes.length + Long.BYTES;
        final ByteBuffer messageToSign = ByteBuffer.allocate(messageToSignLength);
        messageToSign.put(challenge.getChallenge().toByteArray());
        messageToSign.put(intentBytes);
        messageToSign.putLong(epoch);

        final byte[] signedMessage =
            SIGNER.sign(privateKey, messageToSign.array(), mechanism.algorithm().getJvmName());

        return Response.newBuilder()
            .setTime(epoch)
            .setSignature(ByteString.copyFrom(signedMessage))
            .build();
    }

    private Challenge getAndValidateChallenge(byte[] data) throws SaslException {

        try {
            Challenge challenge = Challenge.parseFrom(data);

            final int challengeSize = challenge.getChallenge().size();
            if (challengeSize < MIN_CHALLENGE_SIZE || challengeSize > MAX_CHALLENGE_SIZE) {
                throw new SaslException(
                    "Challenge sent by the server doesn't have the right size - "
                        + challengeSize);
            }

            return challenge;

        } catch (InvalidProtocolBufferException exc) {
            throw new SaslException("Challenge sent by the server is invalid", exc);
        }
    }

    @Override
    public boolean hasInitialResponse() {
        return true;
    }

    @Override
    public boolean isComplete() {
        return state == State.COMPLETE;
    }

    @Override
    public byte[] unwrap(byte[] incoming, int offset, int len) {
        return new byte[0];
    }

    @Override
    public byte[] wrap(byte[] outgoing, int offset, int len) {
        return new byte[0];
    }

    @Override
    public Object getNegotiatedProperty(String propName) {
        return null;
    }

    @Override
    public void dispose() {
    }

    public static class OciSaslClientFactory implements SaslClientFactory {

        @Override
        public SaslClient createSaslClient(
            String[] mechanisms,
            String authorizationId,
            String protocol,
            String serverName,
            Map<String, ?> props,
            CallbackHandler cbh)
            throws SaslException {

            OciMechanism ociMechanism = null;
            for (String mechanism : mechanisms) {
                ociMechanism = OciMechanism.fromMechanismName(mechanism);
                if (ociMechanism != null) {
                    break;
                }
            }
            if (ociMechanism == null) {
                throw new SaslException(
                    String.format(
                        "Requested mechanisms '%s' not supported. Supported mechanisms are '%s'.",
                        Collections.singletonList(mechanisms),
                        OciMechanism.mechanismNames()));
            }

            final Credentials credentials = getCredentials(cbh);

            return new OciSaslClient(ociMechanism, credentials.authProvider, credentials.payload);
        }

        @Override
        public String[] getMechanismNames(Map<String, ?> props) {
            Collection<String> mechanisms = OciMechanism.mechanismNames();
            return mechanisms.toArray(new String[0]);
        }

        private Credentials getCredentials(CallbackHandler callbackHandler) throws SaslException {

            final NameCallback nameCallback = new NameCallback("Payload");
            final PasswordCallback passwordCallback =
                new PasswordCallback("AuthProviderKey", false);
            final OciAuthProviderCallback authProviderCallback = new OciAuthProviderCallback();

            if (authProviderCallback.authProvider() == null) {
                LOG.info(
                    "OciSaslClient: before callbacks - getCredentials() - auth provider is null!");
            } else {
                LOG.info(
                    "OciSaslClient: before callbacks - getCredentials()- auth provider is Not Null!");
            }

            execute(callbackHandler, nameCallback, true);
            execute(callbackHandler, passwordCallback, false);
            execute(callbackHandler, authProviderCallback, false);

            if (authProviderCallback.authProvider() == null) {
                LOG.info(
                    "OciSaslClient: after callbacks - getCredentials() - auth provider is null!");
            } else {
                LOG.info(
                    "OciSaslClient: after callbacks - getCredentials()- auth provider is Not Null!");
            }

            if (authProviderCallback.authProvider() == null
                && passwordCallback.getPassword() == null) {
                throw new SaslException(
                    "Callback handler needs to support either PasswordCallback or OciAuthProviderCallback");
            }

            LOG.info("OciSaslClient: after callbacks - password callback has password - {}",
                new String(passwordCallback.getPassword()));

            OciSaslClient.AuthProviderCache.printCache();

            final BasicAuthenticationDetailsProvider authProvider =
                authProviderCallback.authProvider() != null
                    ? authProviderCallback.authProvider()
                    : OciSaslClient.AuthProviderCache.get(new String(passwordCallback.getPassword()));

            if (authProvider == null) {
                LOG.info(
                    "OciSaslClient:getCredentials() - building creds - auth provider is null!");
            } else {
                LOG.info(
                    "OciSaslClient:getCredentials() - building creds - auth provider is Not Null!");
            }

            final String intent = nameCallback.getName();

            return new Credentials(authProvider, intent);
        }

        static <T extends Callback> void execute(
            CallbackHandler callbackHandler, T callback, boolean required)
            throws SaslException {
            try {
                callbackHandler.handle(new Callback[]{callback});
            } catch (UnsupportedCallbackException exc) {
                if (required) {
                    throw new SaslException(
                        exc.getCallback().getClass().getSimpleName()
                            + " is not supported by the callback handler",
                        exc);
                }
            } catch (IOException exc) {
                throw new SaslException("Unexpected IOException during callback handler", exc);
            }
        }

        private static final class Credentials {

            private final BasicAuthenticationDetailsProvider authProvider;
            private final String payload;

            private Credentials(BasicAuthenticationDetailsProvider authProvider, String payload) {
                this.authProvider = authProvider;
                this.payload = payload;
            }
        }
    }

    static class AuthProviderCache {

        static {
            LOG.info("initializing auth provider cache,");
        }
        private static final Map<String, BasicAuthenticationDetailsProvider> authProvidersCache =
            new HashMap<>();

        static String cache(BasicAuthenticationDetailsProvider authProvider) {
            String key = UUID.randomUUID().toString();
            LOG.info("adding cache entry, key - {}, provider - {}", key, authProvider);
            authProvidersCache.put(key, authProvider);
            printCache();
            return key;
        }

        static BasicAuthenticationDetailsProvider get(String key) {
            return authProvidersCache.get(key);
        }

        static void printCache() {
            LOG.info("cache has {} entries", authProvidersCache.size());
            for (Map.Entry<String, BasicAuthenticationDetailsProvider> entry : authProvidersCache
                .entrySet()) {
                LOG.info("cache key - {}, value - {}", entry.getKey(), entry.getValue());
            }
        }
    }

    @RequiredArgsConstructor
    private static final class OciPrivateKey {

        private final String keyId;
        private final InputStream privateKey;
        private final char[] passphraseCharacters;
    }
}
