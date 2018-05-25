#ifndef ETEDRAWKEYGENDIALOG_H
#define ETEDRAWKEYGENDIALOG_H

#include <QTime>
#include <QDialog>
#include <QtGlobal>
#include <QProcess>
#include <QDebug>
#include <QCryptographicHash>

namespace Ui {
class ETEdrawKeygenDialog;
}

class ETEdrawKeygenDialog : public QDialog
{
    Q_OBJECT

public:
    explicit ETEdrawKeygenDialog(QWidget *parent = 0);
    ~ETEdrawKeygenDialog();

    QString DeviceIdentifier();
    void RandString(QString & randString, int maxLength);

private slots:
    void on_btnKeygen_clicked();
    void readFromStdOut();

private:
    QProcess *cardProcess;
    QString  m_strPublicKey;
    QString  m_strPrivateKey;
    Ui::ETEdrawKeygenDialog *ui;
};

#endif // ETEDRAWKEYGENDIALOG_H
