/**
 * Copyright 2004-2013 Crypto-Pro. All rights reserved.
 * Программный код, содержащийся в этом файле, предназначен
 * для целей обучения. Может быть скопирован или модифицирован
 * при условии сохранения абзацев с указанием авторства и прав.
 *
 * Данный код не может быть непосредственно использован
 * для защиты информации. Компания Крипто-Про не несет никакой
 * ответственности за функционирование этого кода.
 */
package ru.CryptoPro.mycryptopro.util;

/**
 * Служебный интерфейс IContainers содержит список
 * тестовых контейнеров для ГОСТ 34.10-2001 (DH),
 * ГОСТ 34.10-2012 (256) DH и ГОСТ 34.10-2012 (512) DH.
 *
 * 09/12/2013
 *
 */
public interface IContainers {

    /********************** ГОСТ Р 34.10-2001 **********************/

    /**
     * Название контейнера для подписи/шифрования.
     */
    public static final String CLIENT_CONTAINER_NAME = "clientTL.000";

    /**
     * Алиас ключа подписи/шифрования.
     */
    public static final String CLIENT_KEY_ALIAS = "clientTLS";

    /**
     * Пароль ключа подписи/шифрования.
     */
    public static final char[] CLIENT_KEY_PASSWORD = "1".toCharArray();

    /**
     * Название контейнера для шифрования на стороне сервера.
     */
    public static final String SERVER_CONTAINER_NAME = "serverTL.000";

    /**
     * Алиас ключа шифрования на стороне сервера.
     */
    public static final String SERVER_KEY_ALIAS = "serverTLS";

    /**
     * Пароль ключа шифрования на стороне сервера.
     */
    public static final char[] SERVER_KEY_PASSWORD = CLIENT_KEY_PASSWORD;

    /******************** ГОСТ Р 34.10-2012 (256) ********************/

    /**
     * Название контейнера для подписи/шифрования.
     */
    public static final String CLIENT_CONTAINER_2012_256_NAME = "cli12256.000";

    /**
     * Алиас ключа подписи/шифрования.
     */
    public static final String CLIENT_KEY_2012_256_ALIAS = "cli12256";

    /**
     * Пароль ключа подписи/шифрования.
     */
    public static final char[] CLIENT_KEY_2012_256_PASSWORD = "2".toCharArray();

    /**
     * Название контейнера для шифрования на стороне сервера.
     */
    public static final String SERVER_CONTAINER_2012_256_NAME = "ser12256.000";

    /**
     * Алиас ключа шифрования на стороне сервера.
     */
    public static final String SERVER_KEY_2012_256_ALIAS = "ser12256";

    /**
     * Пароль ключа шифрования на стороне сервера.
     */
    public static final char[] SERVER_KEY_2012_256_PASSWORD = CLIENT_KEY_2012_256_PASSWORD;

    /******************** ГОСТ Р 34.10-2012 (512) ********************/

    /**
     * Название контейнера для подписи/шифрования.
     */
    public static final String CLIENT_CONTAINER_2012_512_NAME = "cli12512.000";

    /**
     * Алиас ключа подписи/шифрования.
     */
    public static final String CLIENT_KEY_2012_512_ALIAS = "cli12512";

    /**
     * Пароль ключа подписи/шифрования.
     */
    public static final char[] CLIENT_KEY_2012_512_PASSWORD = "3".toCharArray();

    /**
     * Название контейнера для шифрования на стороне сервера.
     */
    public static final String SERVER_CONTAINER_2012_512_NAME = "ser12512.000";

    /**
     * Алиас ключа шифрования на стороне сервера.
     */
    public static final String SERVER_KEY_2012_512_ALIAS = "ser12512";

    /**
     * Пароль ключа шифрования на стороне сервера.
     */
    public static final char[] SERVER_KEY_2012_512_PASSWORD = CLIENT_KEY_2012_512_PASSWORD;

}
