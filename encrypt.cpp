#include <iostream>
#include <string.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include<openssl/err.h>
#include <openssl/bio.h>

using namespace std;

#define public_key "rsa_public_key2.pem"
#define private_key "rsa_private_key.pem"


char * base64Encode(const char *buffer, int length, bool newLine);
char * base64Decode(char *input, int length, bool newLine);

void encrypt(const char * content, string & encrystr)
{
	unsigned char *p_en;
    RSA *p_rsa;
    FILE *file;
    int flen,rsa_len;

    if((file= fopen(public_key, "r")) == NULL)
	{
        perror("open key file error");
        return ;    
    } 
 
    if((p_rsa = PEM_read_RSA_PUBKEY(file, NULL,NULL,NULL))==NULL)
	{
    //if((p_rsa=PEM_read_RSAPublicKey(file,NULL,NULL,NULL))==NULL){  换成这句死活通不过，无论是否将公钥分离源文件
         ERR_print_errors_fp(stdout);
        return ;
    }
  
    flen = strlen(content);

    rsa_len=RSA_size(p_rsa);

    p_en = (unsigned char *)malloc(rsa_len+1);
    memset(p_en,0,rsa_len+1);
	
	int contlen = strlen(content);
	int len = contlen + 2;
	cout<<"length:"<<strlen(content)<<endl;
	
	unsigned char * pt = new unsigned char[len];
	memset(pt, 0, len);

	memcpy(pt+1, content, contlen);

	int ret = RSA_public_encrypt(rsa_len,pt,(unsigned char*)p_en,p_rsa,RSA_NO_PADDING);
	//int ret = RSA_public_encrypt(rsa_len,pt,(unsigned char*)p_en,p_rsa,RSA_PKCS1_PADDING);

    if(ret < 0)
	{
        ERR_print_errors_fp(stdout);
		//cout<<"error happen. ret="<<ret<<endl;
        return ;
    }

    RSA_free(p_rsa);
    fclose(file);

	//base64 encode it
	char * res = base64Encode((char *) p_en, rsa_len+1, true);
	
	//encrystr = string((char *)p_en);
	encrystr = string(res);

	delete[] pt;
}

char * base64Encode(const char *buffer, int length, bool newLine)
{
    BIO *bmem = NULL;
    BIO *b64 = NULL;
    BUF_MEM *bptr;

    b64 = BIO_new(BIO_f_base64());
    if (!newLine) {
        BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    }
    bmem = BIO_new(BIO_s_mem());
    b64 = BIO_push(b64, bmem);
    BIO_write(b64, buffer, length);
    BIO_flush(b64);
    BIO_get_mem_ptr(b64, &bptr);
    BIO_set_close(b64, BIO_NOCLOSE);

    char *buff = (char *)malloc(bptr->length + 1);
    memcpy(buff, bptr->data, bptr->length);
    buff[bptr->length] = 0;
    BIO_free_all(b64);

    return buff;
}

char * base64Decode(char *input, int length, bool newLine)
{
    BIO *b64 = NULL;
    BIO *bmem = NULL;
    char *buffer = (char *)malloc(length);
    memset(buffer, 0, length);
    b64 = BIO_new(BIO_f_base64());
    if (!newLine) {
        BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    }
    bmem = BIO_new_mem_buf(input, length);
    bmem = BIO_push(b64, bmem);
    BIO_read(bmem, buffer, length);
    BIO_free_all(bmem);

    return buffer;
}

void my_decrypt(const char *str, string & decrstr)
{
	unsigned char *p_de;
    RSA *p_rsa;
    FILE *file;
    int rsa_len;

	//先获取私钥的内容
    if((file=fopen(private_key, "r")) == NULL)
	{
        perror("open key file error");
        return ;
    }

	//cout<<"encrypt:"<<str<<endl;	

	//产生RSA对象指针，用私钥内容初始化该RSA对象
    if((p_rsa = PEM_read_RSAPrivateKey(file, NULL,NULL,NULL))==NULL)
	{
        ERR_print_errors_fp(stdout);
        return ;
    }

	//确定解密后的文件大小
    rsa_len=RSA_size(p_rsa);
    p_de=(unsigned char *)malloc(rsa_len+1);
    memset(p_de,0,rsa_len+1);
	
	char * de_base = base64Decode((char *)str, strlen(str), true);	

	//cout<<"debase64"<<de_base<<endl;

    if(RSA_private_decrypt(rsa_len, (unsigned char *)de_base, (unsigned char*)p_de, p_rsa, RSA_NO_PADDING)<0)
	{
        ERR_print_errors_fp(stdout);
        return ;
    }

    RSA_free(p_rsa);
    fclose(file);
	
	decrstr = string((char *)p_de+1);
 }

int main(int argc, char **argv)
{
	if (argc < 2)
	{
		return 0;
	}
	
	string tt;

	
	string rawval;

	for(int i = 1; i < argc; ++i)
	{
		rawval += argv[i];
		rawval += string(" ");
	}

	cout<<"content is:"<<rawval<<endl;
	encrypt(rawval.c_str(), tt);
	
	//encrypt("just for test ", tt);
	if (tt.empty())
	{
		return 0;
	}

	//cout<<tt<<endl;
	cout<<"over"<<endl;

	string dd;
	my_decrypt(tt.c_str(), dd);

	cout<<"after decrypt:"<<dd<<endl;
	return 0;
}

