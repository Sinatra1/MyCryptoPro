package ru.CryptoPro.mycryptopro;

import android.content.Context;
import android.util.Log;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.net.URI;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.util.Collections;
import java.util.concurrent.TimeUnit;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

import kotlin.TypeCastException;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.internal.Intrinsics;
import okhttp3.ConnectionSpec;
import okhttp3.OkHttpClient;
import okhttp3.ResponseBody;
import okhttp3.Call.Factory;
import okhttp3.ConnectionSpec.Builder;

import org.apache.http.client.HttpClient;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import retrofit2.Call;
import retrofit2.Response;
import retrofit2.Retrofit;
import ru.CryptoPro.JCSP.JCSP;
import ru.CryptoPro.JCSP.support.BKSTrustStore;
import ru.CryptoPro.mycryptopro.api.CryptoApi;
import ru.CryptoPro.ssl.Provider;
import ru.cprocsp.ACSP.tools.common.Constants;

public class HttpTSLSreviceJava {

    @Nullable
    private final long MAX_CLIENT_TIMEOUT = 3600000L;
    private final long MAX_THREAD_TIMEOUT = 6000000L;
    @NotNull
    private final String DEFAULT_ENCODING = "windows-1251";

    public final void execute(@NotNull Context context) {
        Intrinsics.checkParameterIsNotNull(context, "context");
        retrofit2.Response<ResponseBody> retrofitResponse = null;

        try {

            /**
             * Для чтения(!) доверенного хранилища доступна
             * реализация CertStore из Java CSP. В ее случае
             * можно не использовать пароль.
             */

            KeyStore ts = KeyStore.getInstance(BKSTrustStore.STORAGE_TYPE, BouncyCastleProvider.PROVIDER_NAME);

            final String trustStorePath = context.getApplicationInfo().dataDir + File.separator +
                    BKSTrustStore.STORAGE_DIRECTORY + File.separator + BKSTrustStore.STORAGE_FILE_TRUST;

            FileInputStream stream = new FileInputStream(trustStorePath);

            ts.load(stream, BKSTrustStore.STORAGE_PASSWORD);

            KeyStore ks = null;

            SSLContext sslCtx = SSLContext.getInstance(Provider.ALGORITHM, Provider.PROVIDER_NAME);

            TrustManagerFactory tmf = TrustManagerFactory.getInstance(Provider.KEYMANGER_ALG, Provider.PROVIDER_NAME);
            tmf.init(ts);

            sslCtx.init(null, tmf.getTrustManagers(), null);

            javax.net.ssl.SSLSocketFactory sslFactory = sslCtx.getSocketFactory();

            X509TrustManager tm = (X509TrustManager) tmf.getTrustManagers()[0];

            ConnectionSpec spec = new ConnectionSpec.Builder(ConnectionSpec.COMPATIBLE_TLS)
                    .tlsVersions(Provider.ALGORITHM)
                    .cipherSuites(Provider.KEYMANGER_ALG)
                    .allEnabledTlsVersions()
                    .supportsTlsExtensions(false)
                    .allEnabledCipherSuites()
                    .build();

            OkHttpClient.Builder builder;
            builder = new OkHttpClient.Builder();
            builder.sslSocketFactory(sslFactory, tm);
            builder.hostnameVerifier(org.apache.http.conn.ssl.SSLSocketFactory.ALLOW_ALL_HOSTNAME_VERIFIER);
            builder.connectTimeout(MAX_CLIENT_TIMEOUT, TimeUnit.MILLISECONDS);
            builder.readTimeout(MAX_CLIENT_TIMEOUT, TimeUnit.MILLISECONDS);
            builder.connectionSpecs(Collections.singletonList(spec));
            OkHttpClient okHttpClient = builder.build();

            Retrofit.Builder retrofitBuilder = new Retrofit.Builder()
                    .baseUrl("https://cpca.cryptopro.ru:443")
                    .callFactory(okHttpClient);

            Retrofit retrofit = retrofitBuilder.build();

            CryptoApi cryptoApi = retrofit.create(CryptoApi.class);
            retrofitResponse = cryptoApi.getData().execute();

            int status = retrofitResponse.raw().code();

            if (retrofitResponse.raw().code() != 200) {
                return;
            } // if

            if (retrofitResponse.body().source() != null) {

                // Получаем размер заголовка.
                InputStream is = retrofitResponse.body().source().inputStream();

                BufferedReader in = new BufferedReader(
                        new InputStreamReader(is, DEFAULT_ENCODING));

                // Выводим ответ.
                String line;
                while ((line = in.readLine()) != null) {
                } // while

                if (in != null) {
                    in.close();
                } // if

            } // if*/

        } catch (Exception e) {
            Log.e(Constants.APP_LOGGER_TAG, "Operation exception", e);
        } finally {

            // if
        }


    }
}
