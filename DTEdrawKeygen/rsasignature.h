#ifndef RSASIGNATURE_H
#define RSASIGNATURE_H
#include <QObject>

#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/bn.h>
#include <openssl/bio.h>
#include <openssl/evp.h>

class RSASignature
{
public:
    RSASignature();

    int public_encrypt(unsigned char * data,int data_len,unsigned char * key, unsigned char *encrypted);
    int private_decrypt(unsigned char * enc_data,int data_len,unsigned char * key, unsigned char *decrypted);
    int private_encrypt(unsigned char * data,int data_len,unsigned char * key, unsigned char *encrypted);
    int public_decrypt(unsigned char * enc_data,int data_len,unsigned char * key, unsigned char *decrypted);

    int public_encrypt(QString &data, QString &keystr, QString &encrypted);
    int private_decrypt(QString &data, QString &keystr, QString &decrypted);
    int private_encrypt(QString &data,QString &keystr, QString &encrypted);
    int public_decrypt(QString &data, QString &keystr, QString &decrypted);

private:
    int padding;
    RSA* createRSA(unsigned char * key,int publi);
};

#endif // RSASIGNATURE_H
