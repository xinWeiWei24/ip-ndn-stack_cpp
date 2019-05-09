//
// Created by mingj on 18-12-23.
//

#include "LibPcapHelper.h"


LibPcapHelper::LibPcapHelper(const string &configFilePath)
        : mPcap(configFilePath), m_socket(service), threadPool(THREAD_POOL_SIZE) {
    JSONCPPHelper jsoncppHelper(configFilePath);
    string filter = jsoncppHelper.getString("pcap_dstmac");
    try {
        mPcap.activate();
        mPcap.setPacketFilter(filter);
        m_socket.assign(mPcap.getFd());
        stop_flag = true;
        threadNum = 0;
        for(int i = 0; i < MAX_THREAD_NUM; i++)
            ndnthread[i] = NULL;
    } catch (const PcapHelper::Error &e) {
        BOOST_THROW_EXCEPTION(PcapHelper::Error(e.what()));
    }
    //asyncRead();
}

void LibPcapHelper::bindNDNHelper(NDNHelper *ndnHelper) {
    this->ndnHelper = ndnHelper;
}

void LibPcapHelper::bindCacheHelper(MapCacheHelper<tuple_p> *cacheHelper) {
    this->cacheHelper = cacheHelper;
}

void LibPcapHelper::bindPendingInterestTable(MapCacheHelper<long> *pendingInterestMap) {
    this->pendingInterestTable = pendingInterestMap;
}


void LibPcapHelper::bindSequenceTable(MapCacheHelper<int> *sequenceTable) {
    this->sequenceTable = sequenceTable;
}


void LibPcapHelper::asyncRead() {
    m_socket.async_read_some(boost::asio::null_buffers(),
                             [this](const auto &e, auto) { this->handleRead(e); });
}


void LibPcapHelper::handleRead(const boost::system::error_code &error) {
    if (error) {
        cout << "error: " << error;
        return;
    }
    auto res = mPcap.readNextPacketAfterDecode();
    auto tuple = std::get<0>(res);
    if (tuple != nullptr && tuple->ipSize < 8600) {
        this->deal(tuple);
//        //放入线程池中执行
//        threadPool.enqueue([tuple](LibPcapHelper * libPcapHelper) {
//            libPcapHelper->deal(tuple);
//        }, this);
    }
    asyncRead();
}

void LibPcapHelper::handleError(const std::string &errorMessage) {
    cerr << "ERROR: " << errorMessage << endl;
    close();
}

void LibPcapHelper::start() {
    cout << "start" << endl;
    //service.run();
    int ret = pthread_create(&this->tid,NULL,runCap,(void*)this);
    if(ret != 0){
        printf("query thread start error : error code = %d\n",ret) ;
    }
}

void LibPcapHelper::close() {
    //free the pcap handler
    if (m_socket.is_open()) {
        // Cancel all outstanding operations and close the socket.
        // Use the non-throwing variants and ignore errors, if any.
        boost::system::error_code error;
        m_socket.cancel(error);
        m_socket.close(error);
    }
    stop_flag = false;
    pthread_join(this->tid, NULL);
    unordered_map<string,int>::iterator i;

    for (i=tuple5.begin();i!=tuple5.end();i++)
    {
        ndnthread[i->second]->stop();
    }

    mPcap.close();
}


/**
 * 抓到包，并解析后，在此函数中处理
 * @param tuple
 */
void LibPcapHelper::deal(tuple_p tuple) {

    if (tuple->key.proto == IPPROTO_TCP || tuple->key.proto == IPPROTO_UDP) {
        string key = this->build4TupleKey(tuple->key.src_ip, tuple->key.dst_ip,
                                               tuple->key.src_port, tuple->key.dst_port);

        if(tuple5.find(key) == tuple5.end())
        {
            int i = 0;

            i = MAX_THREAD_NUM;
            for(int j = 0; j < MAX_THREAD_NUM; j++)
            {
                if(threadUsage[j] == false)
                {
                    if(ndnthread[j])
                    {
                        delete ndnthread[j];
                        ndnthread[j] = NULL;
                        auto ikey = ituple[i];
                        tuple5.erase(ikey);
                    }
                    i = j;
                    break;
                }
            }

            if(i == MAX_THREAD_NUM)
                return ;
            tuple5[key] = i;
            ituple[i] = key;
            string _dataPrefixUUID = ndnHelper->buildName(tuple->key.src_ip, tuple->key.dst_ip,
                                                                 tuple->key.src_port, tuple->key.dst_port, 4);
            string _prePrefixUUID = ndnHelper->buildName(tuple->key.src_ip, tuple->key.dst_ip,
                                                                tuple->key.src_port, tuple->key.dst_port, 3);
            string _keyName = ndnHelper->build4TupleKey(tuple->key.src_ip, tuple->key.dst_ip,
                                                               tuple->key.src_port, tuple->key.dst_port);
            ndnthread[i] = new NDNthread(this->ndnHelper->getRegisterIp(), i,  _dataPrefixUUID, _prePrefixUUID, _keyName);
            queuelist[i].push(tuple);
            threadUsage[i] = true;
        }
        else
        {
            int t = tuple5[key];
            //ndnthread[t]->addTuple(tuple);
            queuelist[t].push(tuple);
        }
    } else {//为其他协议包用原来的方式传输
        string uuid = this->generateUUID();

        auto dataPrefixUUID = ndnHelper->buildName(tuple->key.src_ip, tuple->key.dst_ip,
                                                   tuple->key.src_port, tuple->key.dst_port, 2, uuid);

        ndnHelper->putDataToCache(dataPrefixUUID, tuple);

        auto prefixUUID = ndnHelper->buildName(tuple->key.src_ip, tuple->key.dst_ip,
                                               tuple->key.src_port, tuple->key.dst_port, 1, uuid);

        ndnHelper->expressInterest(prefixUUID);
    }

}

/**
 * 随机生成一个uuid
 * @return
 */
string LibPcapHelper::generateUUID() {
    boost::uuids::uuid a_uuid = boost::uuids::random_generator()(); // 这里是两个() ，因为这里是调用的 () 的运算符重载
    const string tmp_uuid = boost::uuids::to_string(a_uuid);
    return tmp_uuid;
}

string LibPcapHelper::build4TupleKey(uint32_t sip, uint32_t dip, uint16_t sport, uint16_t dport) {
    //网络字节序转主机字节序
    sip = ntohl(sip);
    dip = ntohl(dip);
    sport = ntohs(sport);
    dport = ntohs(dport);

    //得到source ip
    string sourceIP = to_string((sip >> 24) & 0xFF);
    sourceIP.append(".");
    sourceIP.append(to_string((sip >> 16) & 0xFF));
    sourceIP.append(".");
    sourceIP.append(to_string((sip >> 8) & 0xFF));
    sourceIP.append(".");
    sourceIP.append(to_string((sip >> 0) & 0xFF));

    //得到目的 ip
    string dstIP = to_string((dip >> 24) & 0xFF);
    dstIP.append(".");
    dstIP.append(to_string((dip >> 16) & 0xFF));
    dstIP.append(".");
    dstIP.append(to_string((dip >> 8) & 0xFF));
    dstIP.append(".");
    dstIP.append(to_string((dip >> 0) & 0xFF));

    //得到端口号
    string sourcePort = to_string(sport);
    string dstPort = to_string(dport);

    return sourceIP + "/" + dstIP + "/" + sourcePort + "/" + dstPort;
}


