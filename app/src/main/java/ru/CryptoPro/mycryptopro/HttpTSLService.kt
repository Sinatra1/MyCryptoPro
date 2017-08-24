package ru.CryptoPro.mycryptopro

import android.content.Context
import android.util.Log
import okhttp3.ConnectionSpec
import okhttp3.OkHttpClient
import okhttp3.ResponseBody
import org.apache.http.client.HttpClient
import org.apache.http.conn.ssl.SSLSocketFactory
import retrofit2.Retrofit
import ru.CryptoPro.JCSP.support.BKSTrustStore
import ru.CryptoPro.mycryptopro.api.CryptoApi
import ru.CryptoPro.ssl.Provider
import ru.cprocsp.ACSP.tools.common.Constants
import java.io.BufferedReader
import java.io.File
import java.io.FileInputStream
import java.io.InputStreamReader
import java.security.KeyStore
import java.util.concurrent.TimeUnit
import javax.net.ssl.SSLContext
import javax.net.ssl.TrustManagerFactory
import javax.net.ssl.X509TrustManager

open class HttpTSLService {
    val httpClient: HttpClient? = null

    /**
     * Максимальный таймаут ожидания чтения/записи клиентом
     * (мсек).
     */
    val MAX_CLIENT_TIMEOUT: Long = 60 * 60 * 1000

    /**
     * Максимальный таймаут ожидания завершения потока с примером
     * в случае использования интернета (мсек).
     */
    val MAX_THREAD_TIMEOUT: Long = 100 * 60 * 1000

    /**
     * Кодировка по умолчанию для html-страниц в TLS-примерах.
     */
    val DEFAULT_ENCODING = "windows-1251"

    fun execute(context: Context) {
        var retrofitResponse: retrofit2.Response<ResponseBody>? = null

        try {

            /**
             * Для чтения(!) доверенного хранилища доступна
             * реализация CertStore из Java CSP. В ее случае
             * можно не использовать пароль.
             */

            val ts = KeyStore.getInstance("BKS", "BC")

            val trustStorePath = context.getApplicationInfo().dataDir +
                    File.separator + BKSTrustStore.STORAGE_DIRECTORY + File.separator +
                    BKSTrustStore.STORAGE_FILE_TRUST

            ts.load(FileInputStream(trustStorePath), BKSTrustStore.STORAGE_PASSWORD)

            var ks: KeyStore? = null

            val sslCtx = SSLContext.getInstance(Provider.ALGORITHM, Provider.PROVIDER_NAME)

            val tmf = TrustManagerFactory.getInstance(Provider.KEYMANGER_ALG, Provider.PROVIDER_NAME)
            tmf.init(ts)

            sslCtx.init(null, tmf.trustManagers, null)

            val sslFactory = sslCtx.socketFactory

            val tm = tmf.trustManagers[0] as X509TrustManager

            val spec = ConnectionSpec.Builder(ConnectionSpec.COMPATIBLE_TLS)
                    .tlsVersions(Provider.ALGORITHM)
                    .cipherSuites(Provider.KEYMANGER_ALG)
                    .allEnabledTlsVersions()
                    .supportsTlsExtensions(false)
                    .allEnabledCipherSuites()
                    .build()

            val builder: OkHttpClient.Builder
            builder = OkHttpClient.Builder()
            builder.sslSocketFactory(sslFactory, tm)
            builder.hostnameVerifier(SSLSocketFactory.ALLOW_ALL_HOSTNAME_VERIFIER)
            builder.connectTimeout(MAX_CLIENT_TIMEOUT, TimeUnit.MILLISECONDS)
            builder.readTimeout(MAX_CLIENT_TIMEOUT, TimeUnit.MILLISECONDS)
            builder.connectionSpecs(listOf(spec))
            val okHttpClient = builder.build()

            val retrofitBuilder = Retrofit.Builder()
                    .baseUrl("https://cpca.cryptopro.ru:443")
                    .callFactory(okHttpClient)

            val retrofit = retrofitBuilder.build()

            val cryptoApi = retrofit.create<CryptoApi>(CryptoApi::class.java!!)
            retrofitResponse = cryptoApi.getData().execute()

            val status = retrofitResponse.raw().code()

            if (retrofitResponse.raw().code() != 200) {
                return
            } // if

            if (retrofitResponse.body().source() != null) {

                // Получаем размер заголовка.
                val `is` = retrofitResponse.body().source().inputStream()

                val `in` = BufferedReader(
                        InputStreamReader(`is`, DEFAULT_ENCODING))

                // Выводим ответ.
                var line: String
                while (`in`.readLine() != null) {
                    line = `in`.readLine()
                    Log.i(Constants.APP_LOGGER_TAG, line)
                } // while

                `in`?.close() // if

            } // if

        } catch (e: Exception) {
            Log.e(Constants.APP_LOGGER_TAG, "Operation exception", e)
        } finally {
            if (httpClient != null) {
                Log.i(Constants.APP_LOGGER_TAG, "Shutdown http connection.")

                // Важно закрыть соединение, т.к. HeapWorker может убить jvm
                // из-за возможных задержек в finalize.
                httpClient.connectionManager.shutdown()
            } // if
        }

    }

}
