/*
 * Copyright (C) 2017 Jolla Ltd.
 * Contact: Chris Adams <chris.adams@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#include "plugintypes.h"
#include "applicationinteractionview.h"

#include <QtQml/QQmlEngine>
#include <QtQml>

void Sailfish::Secrets::Plugin::SecretsPlugin::initializeEngine(QQmlEngine *, const char *)
{
}

void Sailfish::Secrets::Plugin::SecretsPlugin::registerTypes(const char *uri)
{
    qRegisterMetaType<Sailfish::Secrets::InteractionParameters>("InteractionParameters");
    qRegisterMetaType<Sailfish::Secrets::InteractionParameters::InputType>("InteractionParameters::InputType");
    qRegisterMetaType<Sailfish::Secrets::InteractionParameters::EchoMode>("InteractionParameters::EchoMode");
    qRegisterMetaType<Sailfish::Secrets::InteractionParameters::Operation>("InteractionParameters::Operation");
    QMetaType::registerComparators<Sailfish::Secrets::InteractionParameters>();
    qmlRegisterUncreatableType<Sailfish::Secrets::InteractionParameters>(uri, 1, 0, "InteractionParameters", QLatin1String("InteractionParameters objects cannot be constructed directly in QML"));

    qRegisterMetaType<Sailfish::Secrets::InteractionResponse>("InteractionResponse");
    QMetaType::registerComparators<Sailfish::Secrets::InteractionResponse>();
    qmlRegisterUncreatableType<Sailfish::Secrets::InteractionResponse>(uri, 1, 0, "InteractionResponse", QLatin1String("InteractionResponse objects cannot be constructed directly in QML"));

    qRegisterMetaType<Sailfish::Secrets::Result>("Result");
    QMetaType::registerComparators<Sailfish::Secrets::Result>();
    qmlRegisterUncreatableType<Sailfish::Secrets::Result>(uri, 1, 0, "Result", QLatin1String("Result objects cannot be constructed directly in QML"));

    qRegisterMetaType<Sailfish::Secrets::Secret>("Secret");
    QMetaType::registerComparators<Sailfish::Secrets::Secret>();
    qmlRegisterUncreatableType<Sailfish::Secrets::Secret>(uri, 1, 0, "Secret", QLatin1String("Secret objects cannot be constructed directly in QML"));

    qmlRegisterType<Sailfish::Secrets::PluginInfoRequest>(uri, 1, 0, "PluginInfoRequest");
    qmlRegisterType<Sailfish::Secrets::CollectionNamesRequest>(uri, 1, 0, "CollectionNamesRequest");
    qmlRegisterType<Sailfish::Secrets::CreateCollectionRequest>(uri, 1, 0, "CreateCollectionRequest");
    qmlRegisterType<Sailfish::Secrets::DeleteCollectionRequest>(uri, 1, 0, "DeleteCollectionRequest");
    qmlRegisterType<Sailfish::Secrets::StoreSecretRequest>(uri, 1, 0, "StoreSecretRequest");
    qmlRegisterType<Sailfish::Secrets::StoredSecretRequest>(uri, 1, 0, "StoredSecretRequest");
    qmlRegisterType<Sailfish::Secrets::FindSecretsRequest>(uri, 1, 0, "FindSecretsRequest");
    qmlRegisterType<Sailfish::Secrets::DeleteSecretRequest>(uri, 1, 0, "DeleteSecretRequest");
    qmlRegisterType<Sailfish::Secrets::InteractionRequest>(uri, 1, 0, "InteractionRequest");

    qmlRegisterType<Sailfish::Secrets::Plugin::ApplicationInteractionView>(uri, 1, 0, "ApplicationInteractionView");
    qmlRegisterType<Sailfish::Secrets::Plugin::SecretManager>(uri, 1, 0, "SecretManager");
}

Sailfish::Secrets::Plugin::SecretManager::SecretManager(QObject *parent)
    : Sailfish::Secrets::SecretManager(parent)
{
}

Sailfish::Secrets::Plugin::SecretManager::~SecretManager()
{
}

Sailfish::Secrets::Result Sailfish::Secrets::Plugin::SecretManager::constructResult() const
{
    return Sailfish::Secrets::Result();
}

Sailfish::Secrets::Secret Sailfish::Secrets::Plugin::SecretManager::constructSecret() const
{
    return Sailfish::Secrets::Secret();
}

Sailfish::Secrets::InteractionParameters Sailfish::Secrets::Plugin::SecretManager::constructInteractionParameters() const
{
    return Sailfish::Secrets::InteractionParameters();
}

Sailfish::Secrets::InteractionResponse Sailfish::Secrets::Plugin::SecretManager::constructInteractionResponse() const
{
    return Sailfish::Secrets::InteractionResponse();
}
