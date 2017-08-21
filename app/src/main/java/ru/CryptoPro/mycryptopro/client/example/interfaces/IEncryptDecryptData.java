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
package ru.CryptoPro.mycryptopro.client.example.interfaces;

import ru.CryptoPro.mycryptopro.util.AlgorithmSelector;

/**
 * Служебный класс IEncryptDecryptData предназначен для
 * реализации примеров шифрования.
 *
 * 27/05/2013
 *
 */
public abstract class IEncryptDecryptData extends ISignData {

    /**
     * Алгоритмы провайдера. Используются на стороне клиента.
     */
    protected AlgorithmSelector clientAlgSelector = null;

    /**
     * Алгоритмы провайдера. Используются на стороне сервера.
     */
    protected AlgorithmSelector serverAlgSelector = null;

    /**
     * Конструктор.
     *
     * @param adapter Настройки примера.
     */
    protected IEncryptDecryptData(ContainerAdapter adapter) {

        super(adapter, false); // ignore

        clientAlgSelector = AlgorithmSelector.getInstance(adapter.getProviderType());
        serverAlgSelector = AlgorithmSelector.getInstance(adapter.getProviderType());

    }

}
