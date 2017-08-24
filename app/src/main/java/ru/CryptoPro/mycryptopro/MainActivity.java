package ru.CryptoPro.mycryptopro;

import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.os.Bundle;
import android.support.annotation.NonNull;
import android.support.v4.app.FragmentActivity;
import android.support.v4.content.ContextCompat;
import android.support.v7.app.AppCompatActivity;
import android.support.v7.widget.AppCompatButton;
import android.util.Log;
import android.view.View;
import android.widget.Button;

import java.io.File;
import java.security.Provider;
import java.security.Security;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

import ru.CryptoPro.CAdES.CAdESConfig;
import ru.CryptoPro.JCPxml.XmlInit;
import ru.CryptoPro.JCSP.CSPConfig;
import ru.CryptoPro.JCSP.JCSP;
import ru.CryptoPro.JCSP.support.BKSTrustStore;
import ru.CryptoPro.mycryptopro.client.example.InstallCAdESTestTrustCertExample;
import ru.CryptoPro.mycryptopro.util.IContainers;
import ru.CryptoPro.reprov.RevCheck;
import ru.CryptoPro.ssl.util.cpSSLConfig;
import ru.cprocsp.ACSP.tools.common.CSPTool;
import ru.cprocsp.ACSP.tools.common.Constants;
import ru.cprocsp.ACSP.tools.common.RawResource;

public class MainActivity extends FragmentActivity {


    /**
     * Java-провайдер Java CSP.
     */
    private static Provider defaultKeyStoreProvider = null;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        // 2. Инициализация провайдеров: CSP и java-провайдеров
        // (Обязательная часть).

        if (!initCSPProviders()) {
            Log.i(Constants.APP_LOGGER_TAG, "Couldn't initialize CSP.");
            return;
        } // if

        initJavaProviders();

        installContainers();

        final Context context = this;

        /*try {
            InstallCAdESTestTrustCertExample cert = new InstallCAdESTestTrustCertExample(this);
            cert.saveTrustCertAll();
        } catch (Exception e) {
            Log.e(Constants.APP_LOGGER_TAG, e.getMessage(), e);
        }*/


        AppCompatButton btExecuteButton = (AppCompatButton) findViewById(R.id.btExamplesExecute);

        // Выполнение примера.
        btExecuteButton.setOnClickListener(new View.OnClickListener() {

            @Override
            public void onClick(View v) {

                Thread thread = new Thread(new Runnable() {

                    @Override
                    public void run() {
                        try  {
                            HttpTSLSreviceJava ht = new HttpTSLSreviceJava();
                            ht.execute(context);

                        } catch (Exception e) {
                            e.printStackTrace();
                        }
                    }
                });

                thread.start();
            }

        });


    }

    /************************ Инициализация провайдера ************************/

    /**
     * Инициализация CSP провайдера.
     *
     * @return True в случае успешной инициализации.
     */
    private boolean initCSPProviders() {

        // Инициализация провайдера CSP. Должна выполняться
        // один раз в главном потоке приложения, т.к. использует
        // статические переменные.
        //
        // 1. Создаем инфраструктуру CSP и копируем ресурсы
        // в папку. В случае ошибки мы, например, выводим окошко
        // (или как-то иначе сообщаем) и завершаем работу.

        int initCode = CSPConfig.init(this);
        boolean initOk = initCode == CSPConfig.CSP_INIT_OK;

        // Если инициализация не удалась, то сообщим об ошибке.
        if (!initOk) {
            String str = "";

            switch (initCode) {

                // Не передан контекст приложения (null). Он необходим,
                // чтобы произвести копирование ресурсов CSP, создание
                // папок, смену директории CSP и т.п.
                case CSPConfig.CSP_INIT_CONTEXT:
                    str = "Couldn't initialize context.";
                    break;

                /**
                 * Не удается создать инфраструктуру CSP (папки): нет
                 * прав (нарушен контроль целостности) или ошибки.
                 * Подробности в logcat.
                 */
                case CSPConfig.CSP_INIT_CREATE_INFRASTRUCTURE:
                    str = "Couldn't create CSP infrastructure.";
                    break;

                /**
                 * Не удается скопировать все или часть ресурсов CSP -
                 * конфигурацию, лицензию (папки): нет прав (нарушен
                 * контроль целостности) или ошибки.
                 * Подробности в logcat.
                 */
                case CSPConfig.CSP_INIT_COPY_RESOURCES:
                    str = "Couldn't copy CSP resources.";
                    break;

                /**
                 * Не удается задать рабочую директорию для загрузки
                 * CSP. Подробности в logcat.
                 */
                case CSPConfig.CSP_INIT_CHANGE_WORK_DIR:
                    str = "Couldn't change CSP working directory.";
                    break;

                /**
                 * Неправильная лицензия.
                 */
                case CSPConfig.CSP_INIT_INVALID_LICENSE:
                    str = "Invalid CSP serial number.";
                    break;

                /**
                 * Не удается создать хранилище доверенных сертификатов
                 * для CAdES API.
                 */
                case CSPConfig.CSP_TRUST_STORE_FAILED:
                    str = "Couldn't create trust store for CAdES API.";
                    break;

            } // switch

        } // if

        return initOk;
    }

    /**
     * Добавление нативного провайдера JCSP, SSL-провайдера
     * и Revocation-провайдера в список Security.
     * Инициализируется JCPxml, CAdES.
     * <p>
     * Происходит один раз при инициализации.
     * Возможно только после инициализации в CSPConfig!
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

    /**
     * Копирование тестовых контейнеров для подписи, шифрования,
     * обмена по TLS в папку keys.
     */
    private void installContainers() {

        // Имена файлов в контейнере.
        final String[] pseudos = {
                "header.key",
                "masks.key",
                "masks2.key",
                "name.key",
                "primary.key",
                "primary2.key"
        };

        // Список алиасов контейнеров.
        final String[] aliases = {
                IContainers.CLIENT_CONTAINER_NAME,          // ГОСТ 34.10-2001
                IContainers.SERVER_CONTAINER_NAME,          // ГОСТ 34.10-2001
                IContainers.CLIENT_CONTAINER_2012_256_NAME, // ГОСТ 34.10-2012 (256)
                IContainers.SERVER_CONTAINER_2012_256_NAME, // ГОСТ 34.10-2012 (256)
                IContainers.CLIENT_CONTAINER_2012_512_NAME, // ГОСТ 34.10-2012 (512)
                IContainers.SERVER_CONTAINER_2012_512_NAME  // ГОСТ 34.10-2012 (512)
        };

        // Список контейнеров и файлов внутри.
        final Integer[][] containers = {
                {R.raw.clienttls_header, R.raw.clienttls_masks, R.raw.clienttls_masks2, R.raw.clienttls_name, R.raw.clienttls_primary, R.raw.clienttls_primary2},
                {R.raw.servertls_header, R.raw.servertls_masks, R.raw.servertls_masks2, R.raw.servertls_name, R.raw.servertls_primary, R.raw.servertls_primary2},
                {R.raw.cli12256_header, R.raw.cli12256_masks, R.raw.cli12256_masks2, R.raw.cli12256_name, R.raw.cli12256_primary, R.raw.cli12256_primary2},
                {R.raw.ser12256_header, R.raw.ser12256_masks, R.raw.ser12256_masks2, R.raw.ser12256_name, R.raw.ser12256_primary, R.raw.ser12256_primary2},
                {R.raw.cli12512_header, R.raw.cli12512_masks, R.raw.cli12512_masks2, R.raw.cli12512_name, R.raw.cli12512_primary, R.raw.cli12512_primary2},
                {R.raw.ser12512_header, R.raw.ser12512_masks, R.raw.ser12512_masks2, R.raw.ser12512_name, R.raw.ser12512_primary, R.raw.ser12512_primary2}
        };

        // Копирование контейнеров.

        try {

            for (int i = 0; i < containers.length; i++) {

                final Integer[] container = containers[i];
                final Map<Integer, String> containerFiles = new HashMap<Integer, String>();

                for (int j = 0; j < container.length; j++) {
                    containerFiles.put(container[j], pseudos[j]);
                } // for

                installContainer(aliases[i], containerFiles);

            } // for

        } catch (Exception e) {
            Log.e(Constants.APP_LOGGER_TAG, e.getMessage(), e);
        }

    }

    /**
     * Копирование файлов контейнера в папку согласно названию
     * контейнера.
     *
     * @param containerName  Имя папки контейнера.
     * @param containerFiles Список и ссылки на файлы контейнера.
     * @throws Exception
     */
    private void installContainer(String containerName,
                                  Map<Integer, String> containerFiles) throws Exception {

        String resourceDirectory = userName2Dir(this) + File.separator + containerName;
        Log.i(Constants.APP_LOGGER_TAG, "Install container: " +
                containerName + " to resource directory: " + resourceDirectory);

        CSPTool cspTool = new CSPTool(this);

        // Копируем ресурсы  в папку keys.
        RawResource resource = cspTool.createRawResource(
                Constants.CSP_SOURCE_TYPE_CONTAINER, resourceDirectory);

        Iterator<Integer> iterator = containerFiles.keySet().iterator();

        while (iterator.hasNext()) {
            Integer index = iterator.next();
            String fileName = containerFiles.get(index);
            if (!resource.copy(index, fileName)) {
                throw new Exception("Couldn't copy " + fileName);
            } // if
        } // while
    }

    /**
     * Формируем имя папки в формате [uid].[uid] для
     * дальнейшего помещения в нее ключевого контейнера.
     *
     * @param context Контекст формы.
     * @return имя папки.
     * @throws Exception
     */
    public static String userName2Dir(Context context)
            throws Exception {

        ApplicationInfo appInfo = context.getPackageManager()
                .getPackageInfo(context.getPackageName(), 0)
                .applicationInfo;

        return String.valueOf(appInfo.uid) + "." +
                String.valueOf(appInfo.uid);
    }
}
