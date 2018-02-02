/*
 * Copyright (C) 2016 Caliste Damien.
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

#ifndef QASSUANSERVER_H
#define QASSUANSERVER_H

#include <QThread>
#include <QMutex>
#include <QDebug>

#include <assuan.h>
#include <gpg-error.h>

#include <Secrets/secretmanager.h>
#include <Secrets/secret.h>
#include <Secrets/interactionparameters.h>

class QAssuanServer: public QThread
{
    Q_OBJECT

 public:
    QAssuanServer(QObject *parent = 0);
    ~QAssuanServer();

    void start();

 private:
    static const QString Temporary;

    friend gpg_error_t _assuan_cmd_confirm(assuan_context_t, char *);
    friend gpg_error_t _assuan_cmd_getpassphrase(assuan_context_t, char *);
    friend gpg_error_t _assuan_cmd_setdesc(assuan_context_t, char *);
    friend gpg_error_t _assuan_cmd_setkeyinfo(assuan_context_t, char *);
    friend gpg_error_t _assuan_cmd_setprompt(assuan_context_t, char *);
    friend gpg_error_t _assuan_cmd_seterror(assuan_context_t, char *);
    friend gpg_error_t _assuan_cmd_setrepeat(assuan_context_t, char *);
    friend gpg_error_t _assuan_cmd_setok(assuan_context_t, char *);
    friend gpg_error_t _assuan_cmd_setcancel(assuan_context_t, char *);
    friend gpg_error_t _assuan_cmd_stop(assuan_context_t, char *);
    friend gpg_error_t _option_handler(assuan_context_t, const char *, const char *);
    friend void _reset_handler(assuan_context_t);

    Sailfish::Secrets::SecretManager secretManager;
    Sailfish::Secrets::Secret::Identifier cacheId;
    Sailfish::Secrets::InteractionParameters::PromptText prompt;

    bool m_connected;
    assuan_context_t m_ctx;
    bool m_request_stop;

    QString m_ctype;
    QString m_messages;

    void run();

    bool ensureCacheCollection();
    bool requestConfirmation(gpg_error_t *err);
    bool requestPassphrase(gpg_error_t *err);
    bool sendCachedPassphrase(gpg_error_t *err);
    bool sendPassphrase(const QByteArray &pin, gpg_error_t *err);
};

#endif
