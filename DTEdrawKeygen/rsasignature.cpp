#include "rsasignature.h"

RSASignature::RSASignature()
{
    padding = RSA_PKCS1_PADDING;
}

/**
 * @brief RSASignature::createRSA
 * @param key
 * @param publi
 * @return
 */
RSA * RSASignature::createRSA(unsigned char * key, int publi)
{
    RSA *rsa= NULL;
    BIO *keybio ;
    keybio = BIO_new_mem_buf(key, -1);
    if (keybio==NULL)
    {
        return 0;
    }

    rsa = RSA_new();
    if(publi)
    {
        rsa = PEM_read_bio_RSA_PUBKEY(keybio, &rsa,NULL, NULL);
    }
    else
    {
        rsa = PEM_read_bio_RSAPrivateKey(keybio, &rsa,NULL, NULL);
    }

    if(rsa == NULL)
    {
        return 0;
    }

    return rsa;
}

/**
 * @brief RSASignature::public_encrypt
 * @param data
 * @param data_len
 * @param key
 * @param encrypted
 * @return
 */
int RSASignature::public_encrypt(unsigned char * data,int data_len,unsigned char * key, unsigned char *encrypted)
{
    RSA * rsa = createRSA(key,1);
    if(rsa==NULL)
        return 0;
    int result = RSA_public_encrypt(data_len,data,encrypted,rsa,padding);
    return result;
}

/**
 * @brief RSASignature::private_decrypt
 * @param enc_data
 * @param data_len
 * @param key
 * @param decrypted
 * @return
 */
int RSASignature::private_decrypt(unsigned char * enc_data,int data_len,unsigned char * key, unsigned char *decrypted)
{
    RSA * rsa = createRSA(key,0);
    if(rsa==NULL)
        return 0;
    int  result = RSA_private_decrypt(data_len, enc_data, decrypted, rsa, padding);
    return result;
}

/**
 * @brief RSASignature::private_encrypt
 * @param data
 * @param data_len
 * @param key
 * @param encrypted
 * @return
 */
int RSASignature::private_encrypt(unsigned char * data,int data_len,unsigned char * key, unsigned char *encrypted)
{
    RSA * rsa = createRSA(key,0);
    if(rsa==NULL)
        return 0;

    int result = RSA_private_encrypt(data_len,data,encrypted,rsa,padding);
    return result;
}

/**
 * @brief RSASignature::public_decrypt
 * @param enc_data
 * @param data_len
 * @param key
 * @param decrypted
 * @return
 */
int RSASignature::public_decrypt(unsigned char * enc_data,int data_len,unsigned char * key, unsigned char *decrypted)
{
    RSA * rsa = createRSA(key,1);
    if(rsa==NULL)
        return 0;

    int  result = RSA_public_decrypt(data_len,enc_data,decrypted,rsa,padding);
    return result;
}

/**
 * @brief RSASignature::public_encrypt
 * @param data
 * @param keystr
 * @param encrypted
 * @return
 */
int RSASignature::public_encrypt(QString &data, QString &keystr, QString &encrypted)
{
    QByteArray keydata=keystr.toLocal8Bit();
    unsigned char *key= (unsigned char*)strdup(keydata.constData());
    RSA * rsa = createRSA(key,1);
    if( rsa == NULL )
        return 0;
    free(key);
    int rsasize=RSA_size(rsa);
    int exppadding=rsasize;
    int result=-1;
    QByteArray decdata = QByteArray::fromHex(QByteArray::fromStdString(data.toStdString()));
    QByteArray signByteArray;
    int data_len=decdata.length();
    if(data_len>exppadding-11)
        exppadding=exppadding-11;
    int b = 0;
    int s = data_len/(exppadding);
    if(data_len%(exppadding))
        s++;
    for(int i=0; i < s; i++)
    {
        QByteArray subdata={0};
        for(int j=0;j<exppadding;j++)
        {
            if(i*exppadding+j>data_len)
                break;
            subdata[j]=decdata[j+i*exppadding];
        }
        unsigned char *smldata=(unsigned char*)strdup(subdata.constData());//数据分片
        unsigned char smlencrypted[1024]={0};//片段加密数据
        int ret=RSA_public_encrypt(exppadding, smldata, smlencrypted, rsa, padding);
        if(ret>0)
        {
            QByteArray subarray=QByteArray::fromRawData((const char *)smlencrypted,rsasize);
            signByteArray.append(subarray);
            b += ret;
        }

        free(smldata);
    }

    encrypted.append(QString(signByteArray.toHex()));
    result=b;
    return result;
}

/**
 * @brief RSASignature::private_decrypt
 * @param data
 * @param keystr
 * @param decrypted
 * @return
 */
int RSASignature::private_decrypt(QString &data,QString &keystr,QString &decrypted)
{
    QByteArray keydata=keystr.toLocal8Bit();
    unsigned char *key= (unsigned char*)strdup(keydata.constData());//密钥
    RSA * rsa = createRSA(key,0);
    if(rsa==NULL)
        return 0;
    free(key);
    int rsasize=RSA_size(rsa);

    QByteArray signByteArray;
    QByteArray encdata=QByteArray::fromHex(QByteArray::fromStdString( data.toStdString()));
    int data_len=encdata.length();
    int result=0;
    int s=data_len/(rsasize);
    if(data_len%(rsasize))
        s++;
    for(int i=0;i<s;i++)
    {
        QByteArray subdata={0};
        for(int j=0;j<rsasize;j++)
        {
            if(i*rsasize+j>data_len)
                break;
            subdata[j]=encdata[j+i*rsasize];
        }
        unsigned char *smldata=(unsigned char*)subdata.data();
        unsigned char smlencrypted[1024]={0};
        int ret=RSA_private_decrypt(rsasize,smldata,smlencrypted,rsa,padding);
        if(ret>0)
        {
            QByteArray decdata((char*)smlencrypted);
            signByteArray.append(decdata);
            result += ret;
        }
    }
    QByteArray b1= QByteArray::fromBase64(signByteArray,QByteArray::Base64Encoding);

    decrypted.append(QString::fromStdString( b1.toStdString() ));

    return result;
}

/**
 * @brief RSASignature::private_encrypt
 * @param data
 * @param keystr
 * @param encrypted
 * @return
 */
int RSASignature::private_encrypt(QString &data,QString &keystr,QString &encrypted)
{
    QByteArray keydata=keystr.toLocal8Bit();
    unsigned char *key= (unsigned char*)strdup(keydata.constData());//密钥
    RSA * rsa = createRSA(key,0);
    if(rsa==NULL)
        return 0;
    free(key);
    int rsasize=RSA_size(rsa);
    int exppadding=rsasize;

    QByteArray decdata= QByteArray::fromStdString(data.toStdString());
    QByteArray signByteArray;
    int data_len=decdata.length();
    if(data_len > exppadding-11)
        exppadding = exppadding-11;
    int result=0;
    int s=data_len/(exppadding);
    if(data_len%(exppadding))
        s++;
    for(int i=0;i<s;i++)
    {
        //分片加密
        QByteArray subdata={0};
        for(int j=0;j < exppadding;j++)
        {
            if(i*exppadding+j >= data_len)
                break;
            subdata[j]=decdata[j+i*exppadding];
        }

        unsigned char *smldata=(unsigned char*)strdup(subdata.constData());
        unsigned char smlencrypted[1024]={0};
        int length = subdata.length();
        int ret=RSA_private_encrypt(length, smldata, smlencrypted, rsa, padding);
        if(ret>0)
        {
            QByteArray subarray=QByteArray::fromRawData((const char *)smlencrypted,rsasize);
            signByteArray.append(subarray);
            result += ret;
        }

        free(smldata);
    }

    encrypted.append(QString(signByteArray.toHex()));
    return result;
}

/**
 * @brief RSASignature::public_decrypt
 * @param data
 * @param keystr
 * @param decrypted
 * @return
 */
int RSASignature::public_decrypt(QString &data, QString &keystr, QString &decrypted)
{
    QByteArray keydata=keystr.toLocal8Bit();
    unsigned char *key= (unsigned char*)strdup(keydata.constData());
    RSA * rsa = createRSA(key,1);
    if(rsa==NULL)
        return 0;
    free(key);
    int rsasize=RSA_size(rsa);
    QByteArray encdata=QByteArray::fromHex(QByteArray::fromStdString( data.toStdString()));
    QByteArray signByteArray;
    int data_len=encdata.length();
    int result=0;
    int s=data_len/(rsasize);
    if(data_len%(rsasize))
        s++;
    for(int i=0;i<s;i++)
    {
        QByteArray subdata={0};
        for(int j=0;j<rsasize;j++)
        {
            if(i*rsasize+j>data_len)
                break;
            subdata[j]=encdata[j+i*rsasize];
        }
        unsigned char *smldata=(unsigned char*)subdata.data();
        unsigned char smlencrypted[1024]={0};
        int ret = RSA_public_decrypt(rsasize,smldata,smlencrypted,rsa,padding);
        if(ret>0)
        {
            QByteArray decdata((char*)smlencrypted);
            signByteArray.append(decdata);
            result += ret;
        }
    }

    decrypted.append(signByteArray);
    return result;
}
