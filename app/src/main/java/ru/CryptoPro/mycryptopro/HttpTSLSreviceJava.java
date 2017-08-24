package ru.CryptoPro.mycryptopro;

import android.content.Context;
import android.os.Environment;
import android.util.Log;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.security.KeyStore;

import kotlin.jvm.internal.Intrinsics;

import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.conn.ClientConnectionManager;
import org.apache.http.conn.scheme.Scheme;
import org.apache.http.conn.scheme.SchemeRegistry;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.impl.conn.SingleClientConnManager;
import org.apache.http.params.BasicHttpParams;
import org.apache.http.params.HttpConnectionParams;
import org.apache.http.params.HttpParams;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import ru.CryptoPro.JCSP.support.BKSTrustStore;
import ru.CryptoPro.ssl.Provider;
import ru.cprocsp.ACSP.tools.common.Constants;

public class HttpTSLSreviceJava {

    @Nullable
    private final int MAX_CLIENT_TIMEOUT = 3600000;
    private final long MAX_THREAD_TIMEOUT = 6000000L;
    @NotNull
    private final String DEFAULT_ENCODING = "windows-1251";

    public final void execute(@NotNull Context context) {
        Intrinsics.checkParameterIsNotNull(context, "context");

        HttpClient httpClient = null;

        try {

            /**
             * Для чтения(!) доверенного хранилища доступна
             * реализация CertStore из Java CSP. В ее случае
             * можно не использовать пароль.
             */

            KeyStore ts = KeyStore.getInstance(BKSTrustStore.STORAGE_TYPE, BouncyCastleProvider.PROVIDER_NAME);

            String trustStorePath = context.getApplicationInfo().dataDir + File.separator +
                    BKSTrustStore.STORAGE_DIRECTORY + File.separator + BKSTrustStore.STORAGE_FILE_TRUST;

            trustStorePath = Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_MUSIC).getAbsolutePath() + File.separator + ru.CryptoPro.JCSP.support.BKSTrustStore.STORAGE_FILE_TRUST;

            FileInputStream stream = new FileInputStream(trustStorePath);

            try {
                ts.load(stream, BKSTrustStore.STORAGE_PASSWORD);
            } catch (Exception e) {
                Log.e(Constants.APP_LOGGER_TAG, e.getMessage(), e);
            }

            KeyStore ks = null;

            org.apache.http.conn.ssl.SSLSocketFactory socketFactory = new org.apache.http.conn.ssl.SSLSocketFactory(
                    Provider.ALGORITHM, ks, "", ts, null, null);

            socketFactory.setHostnameVerifier(
                    org.apache.http.conn.ssl.SSLSocketFactory.ALLOW_ALL_HOSTNAME_VERIFIER);

            // Регистрируем HTTPS схему.
            Scheme httpsScheme = new Scheme("https", socketFactory, 443);

            SchemeRegistry schemeRegistry = new SchemeRegistry();
            schemeRegistry.register(httpsScheme);

            // Параметры соединения.
            HttpParams params = new BasicHttpParams();
            HttpConnectionParams.setSoTimeout(params, MAX_CLIENT_TIMEOUT);
            ClientConnectionManager cm = new SingleClientConnManager(params, schemeRegistry);
            httpClient = new DefaultHttpClient(cm, params);

            // GET-запрос.
            HttpGet httpget = new HttpGet("https://cpca.cryptopro.ru:443");
            HttpResponse response = httpClient.execute(httpget);
            HttpEntity entity = response.getEntity();

            int status = response.getStatusLine().getStatusCode();
            if (status  != 200) {
                return;
            } // if

            if (entity != null) {

                // Получаем размер заголовка.
                InputStream is = entity.getContent();

                BufferedReader in = new BufferedReader(
                        new InputStreamReader(is, DEFAULT_ENCODING));

                // Выводим ответ.
                String line;
                while((line = in.readLine()) != null) {
                    Log.e("wewe", line);
                } // while

                if (in != null) {
                    in.close();
                } // if

            } // if

        } catch (Exception e) {
            Log.e(Constants.APP_LOGGER_TAG, "Operation exception", e);
        } finally {

            // if
        }


    }
}
