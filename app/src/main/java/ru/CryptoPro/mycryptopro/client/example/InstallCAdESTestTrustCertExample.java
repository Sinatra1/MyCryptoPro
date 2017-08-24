/**
 * $RCSfileInstallCAdESTestTrustCertExample.java,v $
 * version $Revision: 36379 $
 * created 15.09.2014 10:21 by Yevgeniy
 * last modified $Date: 2012-05-30 12:19:27 +0400 (Ср, 30 май 2012) $ by $Author: afevma $
 *
 * Copyright 2004-2014 Crypto-Pro. All rights reserved.
 * Программный код, содержащийся в этом файле, предназначен
 * для целей обучения. Может быть скопирован или модифицирован
 * при условии сохранения абзацев с указанием авторства и прав.
 *
 * Данный код не может быть непосредственно использован
 * для защиты информации. Компания Крипто-Про не несет никакой
 * ответственности за функционирование этого кода.
 */
package ru.CryptoPro.mycryptopro.client.example;

import android.content.Context;
import android.os.Environment;
import android.util.Log;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;

import ru.CryptoPro.JCP.JCP;
import ru.CryptoPro.JCSP.CSPConfig;
import ru.CryptoPro.JCSP.JCSP;
import ru.CryptoPro.JCSP.support.BKSTrustStore;
import ru.CryptoPro.mycryptopro.R;
import ru.cprocsp.ACSP.tools.common.Constants;

/**
 * Класс InstallCAdESTestTrustCertExample реализует пример
 * добавления тестового корневого сертификата в специальное
 * хранилище доверенных сертификатов, которое используется в
 * CAdES API и создается один раз в JInitCSP.init(). В данное
 * хранилище следует помещать те корневые сертификаты, которые
 * будут и должны использоваться при построении цепочек сертификатов
 * в CAdES API по аналогии с cacerts в SUN/IBM JRE.
 * Помимо этого хранилища, в CAdES API используется хранилище
 * доверенных сертификатов AndroidCAStore для загрузки корневых
 * сертификатов, установка сертификатов в которое происходит с помощью
 * "Настройки"->"Безопасность"->"Установить с карты памяти" в
 * Android >= 4).
 *
 * @author Copyright 2004-2014 Crypto-Pro. All rights reserved.
 * @.Version
 */
public class InstallCAdESTestTrustCertExample {

    /**
     * Максимальный таймаут ожидания чтения/записи клиентом
     * (мсек).
     */
    public static final int MAX_CLIENT_TIMEOUT = 60 * 60 * 1000;

    /**
     * Максимальный таймаут ожидания завершения потока с примером
     * в случае использования интернета (мсек).
     */
    public static final int MAX_THREAD_TIMEOUT = 100 * 60 * 1000;

    /**
     * Пароль к хранилищу доверенных сертификатов по умолчанию.
     */
    private static final char[] DEFAULT_TRUST_STORE_PASSWORD = BKSTrustStore.STORAGE_PASSWORD;

    /**
     * Устанавливаемые корневые сертификаты.
     */
    private List<X509Certificate> trustCerts = new ArrayList<X509Certificate>(2);

    /**
     * Путь к хранилищу доверенных сертификатов для установки сертификатов.
     */
    private String trustStore = null;

    /**
     * Файл хранилища.
     */
    private File trustStoreFile = null;

    /**
     * Конструктор. Подготовка списка корневых сертификатов для установки.
     *
     * @throws Exception
     */
    public InstallCAdESTestTrustCertExample(Context context) throws Exception {

        InputStream trustStreamForSigner = null, trustStreamForTsp = null;
        trustStore = Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS).getAbsolutePath() + File.separator + BKSTrustStore.STORAGE_FILE_TRUST;

        checkTrustStore();

        //trustStreamForSigner = context.getResources().openRawResource(R.raw.ext_test_ca);  // root certificate for signer
        trustStreamForTsp = context.getResources().openRawResource(R.raw.ext_tsp_root); // root certificate for tsp

        //loadCert(trustStreamForSigner);
        loadCert(trustStreamForTsp);

    }

    /**
     * Загрузка сертификата из потока в список.
     *
     * @param trustStream Поток данных.
     * @throws Exception
     */
    private void loadCert(InputStream trustStream) throws  Exception {

        try {

            final CertificateFactory factory = CertificateFactory.getInstance("X.509");

            trustCerts.add((X509Certificate) factory.generateCertificate(trustStream));
        } finally {

            if (trustStream != null) {

                try {
                    trustStream.close();
                } catch (IOException e) {
                    ;
                }

            } // if

        }

    }

    public void saveTrustCertAll() throws Exception {

        int  i = 0;
        for (X509Certificate trustCert : trustCerts) {
            saveTrustCert(trustStoreFile, trustCert);
            i++;
        } // for

    }

    /**
     * Проверка существования хранилища.
     *
     * @throws Exception
     */
    private void checkTrustStore() throws Exception {

        trustStoreFile = new File(trustStore);
        if (!trustStoreFile.exists()) {
            trustStoreFile.createNewFile();
        } // if

        if (!trustStoreFile.exists()) {
            throw new Exception("Trust store " + trustStore +
                    " doesn't exist");
        } // if

    }

    /**
     * Сохранение сертификата в хранилище.
     *
     * @param trustStoreFile Файл хранилища.
     * @param trustCert Корневой сертификат, добавляемый в хранилище.
     * @throws Exception
     */
    private void saveTrustCert(File trustStoreFile, X509Certificate
        trustCert)
        throws Exception {

        FileInputStream storeStream = new FileInputStream(trustStore);
        KeyStore keyStore = KeyStore.getInstance(BKSTrustStore.STORAGE_TYPE);
        keyStore.load(null, null);

        // Будущий алиас корневого сертификата в хранилище.
        String trustCertAlias = trustCert.getSerialNumber().toString(16);

        try {
            keyStore.load(storeStream, DEFAULT_TRUST_STORE_PASSWORD);
        } catch (Exception e) {
            Log.e(Constants.APP_LOGGER_TAG, e.getMessage(), e);
        }

        storeStream.close();



        // Добавление сертификата, если его нет.
        boolean needAdd = (keyStore.getCertificateAlias(trustCert) == null);
        if (needAdd) {

            keyStore.setCertificateEntry(trustCertAlias, trustCert);

            FileOutputStream updatedTrustStore = new FileOutputStream(trustStoreFile);
            try {
                keyStore.store(updatedTrustStore, DEFAULT_TRUST_STORE_PASSWORD);
            } catch (Exception e) {
                Log.e(Constants.APP_LOGGER_TAG, e.getMessage(), e);
            }

        } // if
        else {
        } // else

    }

    public boolean isAlreadyInstalled() throws Exception {

        FileInputStream storeStream = new FileInputStream(trustStore);
        KeyStore keyStore = KeyStore.getInstance(BKSTrustStore.STORAGE_TYPE);

        keyStore.load(storeStream, DEFAULT_TRUST_STORE_PASSWORD);
        storeStream.close();

        // Если нет какого-то из сертификатов, то считается, что
        // они не установлены.
        for (X509Certificate crt : trustCerts) {
            if (keyStore.getCertificateAlias(crt) == null) {
                return false;
            } // if
        } // for

        return true;
    }
}
