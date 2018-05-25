#include "etedrawkeygendialog.h"
#include "ui_etedrawkeygendialog.h"
#include "qmessagebox.h"
#include "rsasignature.h"

ETEdrawKeygenDialog::ETEdrawKeygenDialog(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::ETEdrawKeygenDialog)
{
    m_strPublicKey = "-----BEGIN PUBLIC KEY-----\n"
                        "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDi/uSF8XFBK7kJTcuO19uu9fO9\n"
                        "zoYJqqy86P9lS7axqYogUTmPRORtW7nifW0O2/0y50BGO6CXh9tZZZOIcbg7ZL/O\n"
                        "tTL7MVuUM36J3tEJBZ8aIvfgQ84PZmlmGXUvmx0ivZpH1J9VDPMUv/RKOkOtu1Hq\n"
                        "BMVqSUXGfYUvGixpdQIDAQAB\n"
                        "-----END PUBLIC KEY-----";
    m_strPrivateKey = "-----BEGIN RSA PRIVATE KEY-----\n"
                        "MIICXQIBAAKBgQDi/uSF8XFBK7kJTcuO19uu9fO9zoYJqqy86P9lS7axqYogUTmP\n"
                        "RORtW7nifW0O2/0y50BGO6CXh9tZZZOIcbg7ZL/OtTL7MVuUM36J3tEJBZ8aIvfg\n"
                        "Q84PZmlmGXUvmx0ivZpH1J9VDPMUv/RKOkOtu1HqBMVqSUXGfYUvGixpdQIDAQAB\n"
                        "AoGAUANjECe8MSm1TqdCcnZ6NGDz6trqemvT+b7zj4QxwMwvKRcYf/zbvASSMFjf\n"
                        "4VYAGTpUeK05/U/hLNDWQUk8k+D6kjdMKDfieFiEemysPa+hQSnU0TnU9PZdPWRF\n"
                        "9UQWft5tNK/5w6BSfVkviEPkzxUROLiYva7mLy2kRGOysuECQQD4FgsWtzq6KvlW\n"
                        "mjVQDzCvdEgm5L3+EYrMIjooep2pQ4uq2AUijUEZWn5GduoRFbmVTTEz0rZc3gBq\n"
                        "nLorWFQNAkEA6jyeG9YVrxb7OBBIABVGly9HBK98Z4L4/a3kK4rFbhzNMpAMOgci\n"
                        "MM96vZD/F0VCSZZqlLaon8EUs3HZJVEJCQJBAOrKqfn4tcsF6u8MiVJY3gHf8n1k\n"
                        "1W+EmLDz38j5qwdMFv487jcyKp9dJs93sbUzs21bHirmzJL9xLUh2Yw2T20CQHng\n"
                        "mJP7TMURvB1ru0rvxw8bNmSluqFRcKTuOe6+AgRNUCei8/mthIjJLCA+tbwx+U+4\n"
                        "yDQg5pRZLqA/+LCF/aECQQC72Tt/DMOdenwkgZG4Ya9WtD4mED0Yu4kMP39h5QgS\n"
                        "g13OChQgSdGlHS+MOo4htrUymyjkejn62L7L/iYLudHU\n"
                        "-----END RSA PRIVATE KEY-----";
    ui->setupUi(this);
}

ETEdrawKeygenDialog::~ETEdrawKeygenDialog()
{
    delete ui;
}

void ETEdrawKeygenDialog::readFromStdOut()
{
    QString cardText = cardProcess->readAllStandardOutput();
    qDebug() << cardText;
}

QString ETEdrawKeygenDialog::DeviceIdentifier()
{
// MACOSX
#ifdef Q_OS_DARWIN64
    QByteArray result;
    QString uuid;
    QString lic;

    QProcess *proc = new QProcess();
    QString qCmd = "ioreg -c IOPlatformExpertDevice";
    proc->start(qCmd);

    proc->waitForFinished(1000);
    QByteArray qOutput = proc->readAllStandardOutput();
    QList<QByteArray> list = qOutput.split('\n');
    QList<QByteArray>::iterator itor = list.begin();
    for ( ; itor != list.end(); itor++) {
        QString strline = QString(*itor);
        if ( strline.contains("IOPlatformUUID", Qt::CaseSensitive) ) {
            QString target = strline.split('=')[1];
            target = target.trimmed();
            target = target.replace(" ", "");
            target = target.replace("\"", "");

            uuid = target;
            continue;
        }

        if ( strline.contains("IOPlatformSerialNumber", Qt::CaseSensitive) ) {
            QString target = strline.split('=')[1];
            target = target.trimmed();
            target = target.replace(" ", "");
            target = target.replace("\"", "");

            lic = target;
            continue;
        }

        if ( uuid.length() > 0 && lic.length() > 0 ) {
            break;
        }
    }

    QByteArray hashResult = QCryptographicHash::hash(QByteArray(QString(uuid + "-" + lic).toLatin1()), QCryptographicHash::Md5);
    result.append(hashResult.toHex().mid(5, 4));

    hashResult = QCryptographicHash::hash(uuid.toLatin1(), QCryptographicHash::Md5);
    result.append(hashResult.toHex().mid(5, 4));

    hashResult = QCryptographicHash::hash(lic.toLatin1(), QCryptographicHash::Md5);
    result.append(hashResult.toHex().mid(5, 4));

#endif

// WIN32
#ifdef Q_OS_WIN32
// todo:
#endif
    return result;
}

/**
 * @brief ETEdrawKeygenDialog::RandString
 * @param randString
 * @param maxLength
 */
void ETEdrawKeygenDialog::RandString(QString & randString, int maxLength){
    QString tmp = QString("0123456789ABCDEFGH");
    QString str = QString();
    QTime t;
    t= QTime::currentTime();
    qsrand(t.msec()+t.second()*1000);
    for(int i=0;i<maxLength;i++) {
        int ir = qrand()%tmp.length();
        str[i] = tmp.at(ir);
    }

    randString = str;
}

void ETEdrawKeygenDialog::on_btnKeygen_clicked()
{
    QString strActCode;
    QString strLicCode;
    QString strTmpData;
    QString identifier;

    RSASignature rsaer;

    RandString(strTmpData, 8);
    RandString(strLicCode, 20);

    identifier = this->DeviceIdentifier();

    if ( identifier.length() <= 0) {
        QMessageBox::critical(this, "Error", "Get system identification failed!");
        return;
    }

    identifier.append(strTmpData.toLower());
    rsaer.private_encrypt(identifier, m_strPrivateKey, strActCode);

    ui->editLicenseCode->setText(strLicCode.toUpper());
    ui->editActivationCode->setText(strActCode);
}
