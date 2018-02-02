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

#include <QCoreApplication>
#include "qassuanserver.h"

class Pinentry : public QCoreApplication
{
public:
    Pinentry(int argc, char **argv)
        : QCoreApplication(argc, argv) {setApplicationName(QStringLiteral("pinentry"));};
    ~Pinentry() {};
public slots:
    void onStop()
    {
        exit(0);
    }
};

int main(int argc, char **argv)
{
    Pinentry pin(argc, argv);
    QAssuanServer server;

    pin.connect(&server, &QAssuanServer::finished, &pin, &Pinentry::onStop);
    server.start();

    return pin.exec();
}
