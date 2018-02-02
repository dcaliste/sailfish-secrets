/*
 * Copyright (C) 2018 Caliste Damien.
 * Contact: Damien Caliste <dcaliste@free.fr>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; version 2 only.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

#include "qassuanserver.h"

#include <Secrets/storesecretrequest.h>
#include <Secrets/storedsecretrequest.h>
#include <Secrets/deletesecretrequest.h>
#include <Secrets/createcollectionrequest.h>

const QString QAssuanServer::Temporary = QStringLiteral("Temporary");

// To be removed when upgrading libassuan to a modern version using gpg-error.
typedef int (*OptionHandler)(assuan_context_t, const char*, const char*);
typedef int (*CmdHandler)(assuan_context_t, char *);

void _reset_handler(assuan_context_t ctx)
{
    fprintf(stderr, "%s\n", __func__);
    QAssuanServer *self = static_cast<QAssuanServer*>(assuan_get_pointer(ctx));

    self->cacheId.setName(QString());
    self->m_description.clear();
    self->m_prompt.clear();
}

gpg_error_t _option_handler(assuan_context_t ctx, const char *key, const char *value)
{
    fprintf(stderr, "%s '%s:%s'\n", __func__, key, value);

    QAssuanServer *self = static_cast<QAssuanServer*>(assuan_get_pointer(ctx));

    if (!strcmp(key, "no-grab") && !*value)
        return 0; // Silently ignore.
    else if (!strcmp(key, "grab") && !*value)
        return 0; // Silently ignore.
    else if (!strcmp(key, "debug-wait")) {
        return 0; // Silently ignore.
    } else if (!strcmp(key, "display")) {
        return 0; // Silently ignore.
    } else if (!strcmp(key, "ttyname")) {
        return 0; // Silently ignore.
    } else if (!strcmp(key, "ttytype")) {
        return 0; // Silently ignore.
    } else if (!strcmp(key, "lc-ctype")) {
        self->m_ctype = value;
    } else if (!strcmp(key, "lc-messages")) {
        self->m_messages = value;
    } else if (!strcmp(key, "parent-wid")) {
        return 0; // Silently ignore.
    } else if (!strcmp(key, "touch-file")) {
        return 0; // Silently ignore.
    } else if (!strcmp(key, "default-ok")) {
        return 0; // Silently ignore.
    } else if (!strcmp(key, "default-cancel")) {
        return 0; // Silently ignore.
    } else if (!strcmp(key, "default-prompt")) {
        return 0; // Silently ignore.
    } else if (!strcmp(key, "default-pwmngr")) {
        return 0; // Silently ignore.
    } else if (!strcmp(key, "allow-external-password-cache") && !*value) {
        return 0; // Silently ignore.
    } else if (!strcmp(key, "allow-emacs-prompt") && !*value) {
        return gpg_error (GPG_ERR_NOT_SUPPORTED);
    } else if (!strcmp(key, "invisible-char")) {
        return 0; // Silently ignore.
    } else
        return gpg_error (GPG_ERR_UNKNOWN_OPTION);
    return 0;
}

// static gpg_error_t cmd_settitle(assuan_context_t ctx, char *line)
// {
//   fprintf(stderr, "%s\n", __func__);

//   QAssuanServer *self = static_cast<QAssuanServer*>(assuan_get_pointer(ctx));
//   decode(self->m_title, line);
//   return 0;
// }

gpg_error_t _assuan_cmd_setdesc(assuan_context_t ctx, char *line)
{
    fprintf(stderr, "%s '%s'\n", __func__, line);

    QAssuanServer *self = static_cast<QAssuanServer*>(assuan_get_pointer(ctx));
    self->m_description = QByteArray::fromPercentEncoding(line);
    return 0;
}

gpg_error_t _assuan_cmd_setprompt(assuan_context_t ctx, char *line)
{
    fprintf(stderr, "%s '%s'\n", __func__, line);

    QAssuanServer *self = static_cast<QAssuanServer*>(assuan_get_pointer(ctx));
    self->m_prompt = QByteArray::fromPercentEncoding(line);
    return 0;
}

gpg_error_t _assuan_cmd_setrepeat(assuan_context_t ctx, char *line)
{
    fprintf(stderr, "%s '%s'\n", __func__, line);

    QAssuanServer *self = static_cast<QAssuanServer*>(assuan_get_pointer(ctx));
    self->cacheId.setName(QString());

    return 0;
}

/* The data provided at LINE may be used by pinentry implementations
   to identify a key for caching strategies of its own.  The empty
   string and --clear mean that the key does not have a stable
   identifier.  */
gpg_error_t _assuan_cmd_setkeyinfo(assuan_context_t ctx, char *line)
{
    fprintf(stderr, "%s '%s'\n", __func__, line);

    QAssuanServer *self = static_cast<QAssuanServer*>(assuan_get_pointer(ctx));
    self->cacheId.setName((*line && strcmp(line, "--clear") !=0) ? line : QString());

    return 0;
}

gpg_error_t _assuan_cmd_get_passphrase(assuan_context_t ctx, char *line)
{
    gpg_error_t rc;

    fprintf(stderr, "%s '%s'\n", __func__, line);

    QAssuanServer *self = static_cast<QAssuanServer*>(assuan_get_pointer(ctx));
    if (self->sendCachedPassphrase(&rc))
        return rc;
    if (self->requestPassphrase(&rc))
        return rc;
    return assuan_send_data(ctx, NULL, 0);
}

#define PACKAGE_VERSION "0.0.1"
/* GETINFO <what>

   Multipurpose function to return a variety of information.
   Supported values for WHAT are:

     version     - Return the version of the program.
     pid         - Return the process id of the server.
 */
static gpg_error_t _assuan_cmd_getinfo(assuan_context_t ctx, char *line)
{
    int rc = 0;
    fprintf(stderr, "%s\n", __func__);

    if (!strcmp(line, "version")) {
        const char *s = PACKAGE_VERSION;
        rc = assuan_send_data (ctx, s, strlen (s));
    } else if (!strcmp(line, "pid")) {
        char numbuf[50];

        snprintf (numbuf, sizeof numbuf, "%lu", (unsigned long)getpid ());
        rc = assuan_send_data(ctx, numbuf, strlen (numbuf));
    } else {
        rc = gpg_error(GPG_ERR_ASS_PARAMETER);
    }
    return rc;
}

gpg_error_t _assuan_cmd_stop(assuan_context_t ctx, char *line)
{
    fprintf(stderr, "%s '%s'\n", __func__, line);

    // assuan_set_flag(ctx, ASSUAN_FORCE_CLOSE, 1);
    QAssuanServer *self = static_cast<QAssuanServer*>(assuan_get_pointer(ctx));
    self->m_request_stop = true;

    return 0;
}

// /* CLEARPASSPHRASE <cacheid>

//    Clear the cache passphrase associated with the key identified by
//    cacheid.
//  */
// static gpg_error_t cmd_clear_passphrase(assuan_context_t ctx, char *line)
// {
//   (void)ctx;
//   fprintf(stderr, "%s\n", __func__);

//   if (! line)
//     return gpg_error (GPG_ERR_ASS_INV_VALUE);

//   /* Remove leading and trailing white space.  */
//   while (*line == ' ')
//     line ++;
//   while (line[strlen (line) - 1] == ' ')
//     line[strlen (line) - 1] = 0;

//   switch (password_cache_clear (line))
//     {
//     case 1: return 0;
//     case 0: return gpg_error (GPG_ERR_ASS_INV_VALUE);
//     default: return gpg_error (GPG_ERR_ASS_GENERAL);
//     }
// }

/* Tell the assuan library about our commands.  */
static gpg_error_t register_commands(assuan_context_t ctx)
{
  static struct
  {
    const char *name;
    int (*handler) (assuan_context_t, char *line);
  } table[] =
    {
      { "SETDESC",        (CmdHandler)_assuan_cmd_setdesc },
      { "SETPROMPT",      (CmdHandler)_assuan_cmd_setprompt },
      { "SETKEYINFO",     (CmdHandler)_assuan_cmd_setkeyinfo },
      { "SETREPEAT",      (CmdHandler)_assuan_cmd_setrepeat },
      // { "SETREPEATERROR", (CmdHandler)cmd_setrepeaterror },
      // { "SETERROR",   (CmdHandler)cmd_seterror },
      // { "SETOK",      (CmdHandler)cmd_setok },
      // { "SETNOTOK",   (CmdHandler)cmd_setnotok },
      // { "SETCANCEL",  (CmdHandler)cmd_setcancel },
      { "GETPIN",         (CmdHandler)_assuan_cmd_get_passphrase },
      { "GET_PASSPHRASE", (CmdHandler)_assuan_cmd_get_passphrase },
      // { "CONFIRM",    (CmdHandler)cmd_confirm },
      // { "MESSAGE",    (CmdHandler)cmd_message },
      // { "SETQUALITYBAR", (CmdHandler)cmd_setqualitybar },
      // { "SETQUALITYBAR_TT", (CmdHandler)cmd_setqualitybar_tt },
      { "GETINFO",    (CmdHandler)_assuan_cmd_getinfo },
      // { "SETTITLE",   (CmdHandler)cmd_settitle },
      // { "SETTIMEOUT", (CmdHandler)cmd_settimeout },
      // { "CLEARPASSPHRASE", (CmdHandler)cmd_clear_passphrase },
      { "STOP",           (CmdHandler)_assuan_cmd_stop },
      { NULL, NULL }
    };
  int i, j;
  gpg_error_t rc;

  for (i = j = 0; table[i].name; i++) {
      rc = assuan_register_command(ctx, table[i].name, table[i].handler);
      if (rc)
          return rc;
  }
  return 0;
}

QAssuanServer::QAssuanServer(QObject *parent)
    : QThread(parent)
    , secretManager(Sailfish::Secrets::SecretManager::SynchronousInitialisationMode)
    , m_connected(false)
    , m_request_stop(false)
{
    gpg_error_t rc;
    int filedesc[2];

    filedesc[0] = 0;
    filedesc[1] = 1;
    rc = assuan_init_pipe_server(&m_ctx, filedesc);
    if (rc) {
        qWarning() << "failed to initialize the server: " << gpg_strerror(rc);
        return;
    }
    m_connected = true;
    rc = register_commands(m_ctx);
    if (rc) {
        qWarning() << "failed to the register commands with Assuan: " << gpg_strerror(rc);
        assuan_deinit_server(m_ctx);
        return;
    }

    assuan_set_pointer(m_ctx, this);
    rc = assuan_register_option_handler(m_ctx, (OptionHandler)_option_handler);
    if (rc) {
        qWarning() << "failed to the register option handler with Assuan: " << gpg_strerror(rc);
        assuan_deinit_server(m_ctx);
        return;
    }
    rc = assuan_register_reset_notify(m_ctx, _reset_handler);
    if (rc) {
        qWarning() << "failed to the register reset handler with Assuan: " << gpg_strerror(rc);
        assuan_deinit_server(m_ctx);
        return;
    }

    cacheId.setCollectionName(QStringLiteral("GnuPG"));
    // Ensure collection exists.
    Sailfish::Secrets::CreateCollectionRequest request;
    request.setManager(&secretManager);
    request.setCollectionName(QStringLiteral("GnuPG"));
    request.setAccessControlMode(Sailfish::Secrets::SecretManager::OwnerOnlyMode);
    request.setCollectionLockType(Sailfish::Secrets::CreateCollectionRequest::DeviceLock);
    request.setDeviceLockUnlockSemantic(Sailfish::Secrets::SecretManager::DeviceLockKeepUnlocked);
    request.setStoragePluginName(Sailfish::Secrets::SecretManager::DefaultEncryptedStoragePluginName);
    request.setEncryptionPluginName(Sailfish::Secrets::SecretManager::DefaultEncryptedStoragePluginName);
    request.startRequest();
    request.waitForFinished();
    if (request.result().code() == Sailfish::Secrets::Result::Failed
        && request.result().errorCode() != Sailfish::Secrets::Result::CollectionAlreadyExistsError)
        qWarning() << "Ensuring collection failed:" << request.result().errorMessage();
}

QAssuanServer::~QAssuanServer()
{
    if (isRunning()) {
        terminate();
        wait(500);
    }
    if (m_connected)
        assuan_deinit_server(m_ctx);
}

void QAssuanServer::start()
{
    if (!m_connected)
        return;

    QThread::start();
}

void QAssuanServer::run()
{
    gpg_error_t rc;

    for (;;) {
        rc = assuan_accept(m_ctx);
        if (rc == -1)
            break;
        else if (rc) {
            qWarning() << "Assuan accept problem: " << gpg_strerror(rc);
            break;
        }

        rc = assuan_process(m_ctx);
        if (rc) {
            qWarning() << "Assuan processing failed: " << gpg_strerror(rc);
            continue;
        }

        if (m_request_stop)
            break;
    }
    qDebug() << "Assuan loop finished.";
}

bool QAssuanServer::sendCachedPassphrase(gpg_error_t *err)
{
    gpg_error_t rc;
    Sailfish::Secrets::StoredSecretRequest request;

    if (!cacheId.isValid())
        return false;

    qDebug() << "Starting cache request for" << cacheId.name();
    request.setManager(&secretManager);
    request.setUserInteractionMode(Sailfish::Secrets::SecretManager::SystemInteraction);
    request.setIdentifier(cacheId);
    request.startRequest();
    request.waitForFinished();
    qDebug() << "-> return code" << request.result().code();
    if (request.result().code() != Sailfish::Secrets::Result::Succeeded) {
        qWarning() << request.result().errorMessage();
        return false;
    }

    if (cacheId.name() != Temporary)
        assuan_write_status(m_ctx, "PASSWORD_FROM_CACHE", "");
    rc = assuan_send_data(m_ctx, request.secret().data().constData(),
                          request.secret().data().length());
    if (!rc)
        rc = assuan_send_data(m_ctx, NULL, 0);

    if (err)
        *err = rc;

    if (cacheId.name() == Temporary) {
        Sailfish::Secrets::DeleteSecretRequest del;
        del.setIdentifier(cacheId);
        del.setManager(&secretManager);
        del.setUserInteractionMode(Sailfish::Secrets::SecretManager::SystemInteraction);
        del.startRequest();
        del.waitForFinished();
    }

    return true;
}

bool QAssuanServer::requestPassphrase(gpg_error_t *err)
{
    Sailfish::Secrets::InteractionParameters uiParams;
    Sailfish::Secrets::StoreSecretRequest request;

    request.setManager(&secretManager);
    request.setSecretStorageType(Sailfish::Secrets::StoreSecretRequest::CollectionSecret);
    request.setUserInteractionMode(Sailfish::Secrets::SecretManager::SystemInteraction);

    uiParams.setPromptText(m_description);
    uiParams.setInputType(Sailfish::Secrets::InteractionParameters::AlphaNumericInput);
    uiParams.setEchoMode(Sailfish::Secrets::InteractionParameters::NormalEcho);
    request.setUiParameters(uiParams);

    if (!cacheId.isValid())
        cacheId.setName(Temporary);
    Sailfish::Secrets::Secret pin(cacheId);
    pin.setType(Sailfish::Secrets::Secret::TypeBlob);
    request.setSecret(pin);

    qDebug() << "Starting passphrase request for" << cacheId.name();
    request.startRequest();
    request.waitForFinished();
    qDebug() << "-> return code" << request.result().code();
    if (request.result().code() != Sailfish::Secrets::Result::Succeeded) {
        qWarning() << request.result().errorMessage();
        return false;
    }

    return sendCachedPassphrase(err);
}
