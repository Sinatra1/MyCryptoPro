package ru.CryptoPro.mycryptopro;

import android.os.Bundle;
import android.support.v7.app.AppCompatActivity;
import android.util.Log;

import java.io.File;
import java.security.Provider;
import java.security.Security;

import ru.CryptoPro.CAdES.CAdESConfig;
import ru.CryptoPro.JCPxml.XmlInit;
import ru.CryptoPro.JCSP.JCSP;
import ru.CryptoPro.JCSP.support.BKSTrustStore;
import ru.CryptoPro.reprov.RevCheck;
import ru.CryptoPro.ssl.util.cpSSLConfig;
import ru.cprocsp.ACSP.tools.common.Constants;

public class MainActivity extends AppCompatActivity {

    /**
     * Java-провайдер Java CSP.
     */
    private static Provider defaultKeyStoreProvider = null;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        initJavaProviders();
    }

    /**
     * Добавление нативного провайдера JCSP, SSL-провайдера
     * и Revocation-провайдера в список Security.
     * Инициализируется JCPxml, CAdES.
     *
     * Происходит один раз при инициализации.
     * Возможно только после инициализации в CSPConfig!
     *
     */
    private void initJavaProviders() {

        // Загрузка Java CSP (хеш, подпись, шифрование, генерация контейнеров).

        if (Security.getProvider(JCSP.PROVIDER_NAME) == null) {
            Security.addProvider(new JCSP());
        } // if

        // Загрузка JTLS (TLS).

        // Необходимо переопределить свойства, чтобы использовались
        // менеджеры из cpSSL, а не Harmony.

        Security.setProperty("ssl.KeyManagerFactory.algorithm",
                ru.CryptoPro.ssl.Provider.KEYMANGER_ALG);
        Security.setProperty("ssl.TrustManagerFactory.algorithm",
                ru.CryptoPro.ssl.Provider.KEYMANGER_ALG);

        Security.setProperty("ssl.SocketFactory.provider",
                "ru.CryptoPro.ssl.SSLSocketFactoryImpl");
        Security.setProperty("ssl.ServerSocketFactory.provider",
                "ru.CryptoPro.ssl.SSLServerSocketFactoryImpl");

        if (Security.getProvider(ru.CryptoPro.ssl.Provider.PROVIDER_NAME) == null) {
            Security.addProvider(new ru.CryptoPro.ssl.Provider());
        } // if

        // Провайдер хеширования, подписи, шифрования по умолчанию.
        cpSSLConfig.setDefaultSSLProvider(JCSP.PROVIDER_NAME);

        // Загрузка Revocation Provider (CRL, OCSP).

        if (Security.getProvider(RevCheck.PROVIDER_NAME) == null) {
            Security.addProvider(new RevCheck());
        } // if

        // Инициализация XML DSig (хеш, подпись).

        XmlInit.init();

        // Параметры для Java TLS и CAdES API.

        // Провайдер CAdES API по умолчанию.
        CAdESConfig.setDefaultProvider(JCSP.PROVIDER_NAME);

        // Включаем возможность онлайновой проверки статуса сертификата.
        System.setProperty("com.sun.security.enableCRLDP", "true");
        System.setProperty("com.ibm.security.enableCRLDP", "true");

        // Настройки TLS для генерации контейнера и выпуска сертификата
        // в УЦ 2.0, т.к. обращение к УЦ 2.0 будет выполняться по протоколу
        // HTTPS и потребуется авторизация по сертификату. Указываем тип
        // хранилища с доверенным корневым сертификатом, путь к нему и пароль.

        final String trustStorePath = getApplicationInfo().dataDir + File.separator +
                BKSTrustStore.STORAGE_DIRECTORY + File.separator + BKSTrustStore.STORAGE_FILE_TRUST;

        final String trustStorePassword = String.valueOf(BKSTrustStore.STORAGE_PASSWORD);
        Log.d(Constants.APP_LOGGER_TAG, "Default trust store: " + trustStorePath);

        System.setProperty("javax.net.ssl.trustStoreType", BKSTrustStore.STORAGE_TYPE);
        System.setProperty("javax.net.ssl.trustStore", trustStorePath);
        System.setProperty("javax.net.ssl.trustStorePassword", trustStorePassword);

    }
}
