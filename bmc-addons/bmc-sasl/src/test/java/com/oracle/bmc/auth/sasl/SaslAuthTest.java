package com.oracle.bmc.auth.sasl;


import com.google.common.util.concurrent.Futures;
import com.google.common.util.concurrent.ListenableFuture;
import com.google.common.util.concurrent.ListeningExecutorService;
import com.google.common.util.concurrent.MoreExecutors;
import com.google.protobuf.ByteString;
import com.oracle.bmc.auth.BasicAuthenticationDetailsProvider;
import com.oracle.bmc.auth.sasl.OciSaslClient.AuthProviderCache;
import com.oracle.bmc.auth.sasl.OciSaslClient.OciSaslClientFactory;
import com.oracle.bmc.identity.auth.sasl.messages.OciSaslMessages.Challenge;
import java.io.File;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Executors;
import javax.security.auth.Subject;
import javax.security.sasl.SaslClient;
import lombok.extern.slf4j.Slf4j;
import org.junit.Test;

@Slf4j
public class SaslAuthTest {

    @Test
    public void testCacheUsingClassLoaders() throws Exception {
        URL targetClassUrl = new File("target/classes").toURI().toURL();
        //URL url = new URL("/Users/makelkar/work/bitbucket/streaming-apps/config-adapter");
        URLClassLoader classLoader1 = new URLClassLoader(new URL[]{targetClassUrl}, null);
        URLClassLoader classLoader2 = new URLClassLoader(new URL[]{targetClassUrl}, null);

/*
        Class<?> cacheClass1 = classLoader1
            .loadClass(OciSaslClient.AuthProviderCache.class.getName());
*/
        Class<?> loginModuleClass1 = classLoader1.loadClass(OciLoginModule.class.getName());
        loginModuleClass1.newInstance();
        LOG.info("after loading first module, cache is - ");
        AuthProviderCache.printCache();

        Class<?> loginModuleClass2 = classLoader1.loadClass(OciLoginModule.class.getName());
        LOG.info("after loading second module, cache is - ");

        AuthProviderCache.printCache();


    }

    @Test
    public void testSaslAuth() throws ExecutionException, InterruptedException {

        ListeningExecutorService executorService =
            MoreExecutors.listeningDecorator(Executors.newFixedThreadPool(2));

        OciSaslClientFactory clientFactory = new OciSaslClientFactory();
        Map<String, String> options = new HashMap<>();
        options.put("intent", "streamPoolId:test");
        DummyLoginModule dummyLoginModule = new DummyLoginModule();
        Subject subject = new Subject();

        Callable<String> callable1 = () -> {
            //Subject subject = new Subject();
            dummyLoginModule.initialize(subject, null, null, options);

            String authId = "testId";
            SaslClient client = clientFactory
                .createSaslClient(new String[]{OciMechanism.OCI_RSA_SHA256.mechanismName()}, "test",
                    "SASL_SSL", "testserver", null,
                    new DummyCallbackHandler(authId, subject.getPrivateCredentials().toArray()[0],
                        "realm1"));

            client.evaluateChallenge(new byte[0]);
            Thread.sleep(30 * 1000);
            String challengeString = "thisischallenge string which is really really long";
            Challenge challenge = Challenge.newBuilder()
                .setChallenge(ByteString.copyFrom(challengeString.getBytes(StandardCharsets.UTF_8)))
                .build();
            client.evaluateChallenge(challenge.toByteArray());
            client.dispose();

            return null;
        };

        Callable<String> callable2 = () -> {
            //DummyLoginModule dummyLoginModule2 = new DummyLoginModule();
            dummyLoginModule.initialize(subject, null, null, options);

            String authId = "testId2";
            SaslClient client2 = clientFactory
                .createSaslClient(new String[]{OciMechanism.OCI_RSA_SHA256.mechanismName()}, "test",
                    "SASL_SSL", "testserver", null,
                    new DummyCallbackHandler(authId, subject.getPrivateCredentials().toArray()[0],
                        "realm1"));
            client2.evaluateChallenge(new byte[0]);
            String challengeString = "thisischallenge string which is really really long";
            Challenge challenge = Challenge.newBuilder()
                .setChallenge(ByteString.copyFrom(challengeString.getBytes(StandardCharsets.UTF_8)))
                .build();
            client2.evaluateChallenge(challenge.toByteArray());
            return null;
        };

        List<ListenableFuture<String>> futures = new ArrayList<>();
        futures.add(executorService.submit(callable1));
        futures.add(executorService.submit(callable2));
        Futures.successfulAsList(futures).get();
        executorService.shutdown();


    }
}
