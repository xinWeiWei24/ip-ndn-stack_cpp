#include "RawSocketHelper.h"

/*RawSocketHelper::RawSocketHelper() {
    //创建一个原始套接字
    this->sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
    //this->sockfd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));

    //开启IP_HDRINCL选项，允许IP首部自定义
    const int on = 1;
    if(setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0) {
        exit(-1);
    }
}*/
RawSocketHelper::RawSocketHelper() {
    //创建一个原始套接字
    //this->sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
    this->sockfd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));

    int tempsd = socket(PF_INET,SOCK_DGRAM,0);
    strncpy(this->req.ifr_name,"ens2f0",6);
    int ret = ioctl(tempsd,SIOCGIFINDEX,&this->req);
    close(tempsd);
    
    if(ret == -1) cout<<"level get ens2f0 index err!"<<endl;
    
}

ssize_t RawSocketHelper::sendPacketTo(const void *buffer, size_t len, string &ip, int flag) {
    struct sockaddr_ll address;
    bzero(&address, sizeof(address));
    address.sll_family = AF_PACKET;
    address.sll_protocol = htons(ETH_P_ALL);
    address.sll_ifindex = req.ifr_ifindex;
   // address.sll_pkttype = PACKET_OUTGOING;
    address.sll_halen = htons(6);
    address.sll_addr[0] = 0xb4;
    address.sll_addr[1] = 0x96;
    address.sll_addr[2] = 0x91;
    address.sll_addr[3] = 0x45;
    address.sll_addr[4] = 0xf3;
    address.sll_addr[5] = 0xc2;
   
    return sendto(this->sockfd, buffer, len, flag, (sockaddr *)&address, sizeof(address));
}
/*ssize_t RawSocketHelper::sendPacketTo(const void *buffer, size_t len, string &ip, int flag) {
    sockaddr_in address{};
    bzero(&address, sizeof(address));
   address.sin_family = AF_INET;
    address.sin_addr.s_addr = inet_addr(ip.c_str());
    return sendto(this->sockfd, buffer, len, flag, (sockaddr *)&address, sizeof(address));
}*/
