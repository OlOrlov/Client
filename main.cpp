#include <QCoreApplication>
#include <QTextStream>
#include <QDebug>
#include <QUdpSocket>
#include <QElapsedTimer>

const quint16 portForAuthorization = 8000;
const quint16 portForLogRecord = 8001;
const quint16 msTimeout = 5000;
const QString authWord = "[Auth]";
const QString loginWord = "[Login]";
const QString tokenWord = "[Token]";
const QString msgWord = "[Msg]";

bool send(QHostAddress clientIP, quint16 clientPort,
          QHostAddress serverIP, quint16 serverPort,
          QByteArray msg)
{
    QUdpSocket xmt_sock;
    if ( !xmt_sock.bind(clientIP, clientPort))
    {
        qDebug() << "Failed to bind socket" << xmt_sock.errorString();
        return false;
    }

    xmt_sock.connectToHost(serverIP, serverPort);
    if ( !xmt_sock.waitForConnected(1))
    {
        qDebug() << ("UDP connection timeout");
        return false;
    }

    qint64 r1 = xmt_sock.write(msg);
    if ( r1 != msg.length() )
    {
        qDebug() << ("Msg send failure");
        return false;
    }
    return true;
}

QByteArray receive(QHostAddress clientIP, quint16 clientPort, qint64 receiveTimeout)
{
    QByteArray received;

    QUdpSocket rcv_sock;
    rcv_sock.bind(clientIP, clientPort);

    QElapsedTimer tmr;
    tmr.start();

    while (tmr.elapsed() < receiveTimeout)
    {
        if (rcv_sock.hasPendingDatagrams())
        {
            received.resize(rcv_sock.pendingDatagramSize());
            rcv_sock.readDatagram(received.data(), received.size());
            break;
        }
    }

    return received;
}

int main(int argc, char *argv[])
{
    QCoreApplication a(argc, argv);

    QRegExp ipControl("(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\."
                      "(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\."
                      "(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\."
                      "(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)");
    QTextStream s(stdin);

    printf("Set server IP: ");
    QString ip;
    while (true)
    {
        ip = s.readLine();
        if (ipControl.exactMatch(ip))
            break;
        else
            printf("Incorrect IP\nSet server IP: ");
    }

    QHostAddress serverIP;
    serverIP.setAddress(ip);

    printf("Set client IP: ");
    while (true)
    {
        ip = s.readLine();
        if (ipControl.exactMatch(ip))
            break;
        else
            printf("Incorrect IP\nSet client IP: ");
    }

    QHostAddress clientIP;
    clientIP.setAddress(ip);

    printf("\nSet client port: ");
    quint16 port;

    while (true)
    {
        port = s.readLine().toInt();
        if (port < 1024)
            printf("Incorrect port\nSet port: ");
        else
            break;
    }

    printf("\nSet login: ");
    QString login;

    while (true)
    {
        login = s.readLine();
        if ( (login.size() > 16) || (login.isEmpty()) )
            printf("Incorrect login size\nSet login: ");
        else
            break;
    }


    //Authorization
    printf("\nAttempting to athorize...");
    if (send(clientIP, port, serverIP, portForAuthorization, (authWord + login).toUtf8()))
    {
        auto token = receive(clientIP, port, msTimeout);

        if (token.isEmpty())
        {
            qDebug() << " no token received. Authorization failed.";
        }
        else
        {
            qDebug() << " success, received token" << token.toHex().toUpper();

            printf("\nEnter message. For exit enter 'e'");
            QString msg;
            while (true)
            {
                printf("\n:");
                msg = s.readLine();
                if (msg == "e")
                {
                    break;
                }
                else
                {
                    QByteArray toSend;
                    toSend.append(loginWord);
                    toSend.append(login.toUtf8());
                    toSend.append(tokenWord);
                    toSend.append(token);
                    toSend.append(msgWord);
                    toSend.append(msg.toUtf8());
                    send(clientIP, port, serverIP, portForLogRecord, toSend);
                }
            }
        }
    }

    return a.exec();
}
