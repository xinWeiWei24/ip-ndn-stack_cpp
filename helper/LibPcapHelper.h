//
// Created by mingj on 18-12-23.
//

#ifndef IP_NDN_STACK_CPP_LIBPCAPHELPER_H
#define IP_NDN_STACK_CPP_LIBPCAPHELPER_H

#include <iostream>
#include "RawSocketHelper.h"
#include "JSONCPPHelper.h"
#include "NDNHelper.h"
#include "MapCacheHelper.h"
#include "PcapHelper.h"
#include <string>
#include <boost/uuid/uuid.hpp>
#include <boost/uuid/uuid_io.hpp>
#include <boost/uuid/uuid_generators.hpp>
#include <ndn-cxx/face.hpp>
#include <sys/wait.h>
#include <errno.h>
#include <boost/thread.hpp>
#include <boost/asio.hpp>
#include "ThreadPool.h"

#include<pthread.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <boost/lockfree/queue.hpp>



#define MAX_THREAD_NUM 10

using namespace std;
using namespace ndn;
using namespace IP_NDN_STACK::pcap;

class NDNthread;

class LibPcapHelper {
public:
    explicit
    LibPcapHelper(const string &configFilePath);

    static boost::lockfree::queue<tuple_p,boost::lockfree::capacity<40000>> queuelist[10];
    static bool threadUsage[MAX_THREAD_NUM];


    void start();


    void close();

    string generateUUID();

    void bindNDNHelper(NDNHelper *ndnHelper);

    /**
     * 绑定缓存表
     * @param cacheHelper
     */
    void bindCacheHelper(MapCacheHelper<tuple_p> *cacheHelper);

    /**
     * 绑定悬而未决表
     * @param pendingInterestMap
     */
    void bindPendingInterestTable(MapCacheHelper<long> *pendingInterestMap);

    /**
     * 绑定自增序列号表
     * @param sequenceTable
     */
    void bindSequenceTable(MapCacheHelper<int> *sequenceTable);

    string build4TupleKey(uint32_t sip, uint32_t dip, uint16_t sport, uint16_t dport);

    static void *runCap(void* args)
    {
        LibPcapHelper *_this = (LibPcapHelper*) args;
        while(_this->stop_flag)
        {
            auto res = _this->mPcap.readNextPacketAfterDecode();
            auto tuple = std::get<0>(res);
            if (tuple != nullptr && tuple->ipSize < 8600) {
                _this->deal(tuple);
            }
        }
    }

    bool stop_flag;


protected:
    void
    asyncRead();

    void
    handleRead(const boost::system::error_code &error);

    void
    handleError(const std::string &errorMessage);

private:
    PcapHelper mPcap;
    boost::asio::io_service service;
    boost::asio::posix::stream_descriptor m_socket;
    NDNHelper *ndnHelper;
    MapCacheHelper<tuple_p> *cacheHelper;               //缓存表
    MapCacheHelper<long> *pendingInterestTable;       //悬而未决表
    /**
     * key -> 四元组
     * value -> 代表最后一次处理的该四元组对应的包的编码
     */
    MapCacheHelper<int> *sequenceTable;                 //自增序列号表
    RawSocketHelper rawSocketHelper;

    pthread_t tid;

    unordered_map<string, int> tuple5;
    unordered_map<int, string> ituple;



    int threadNum;

    NDNthread *ndnthread[MAX_THREAD_NUM];

    static const int THREAD_POOL_SIZE = 1;

    ThreadPool threadPool;

    void deal(tuple_p tuple);



};


class NDNthread{
public:
    NDNthread(vector<string> ips, int id1){

        this->id = id1;
        ndnthhelper.setRegisterIp(ips);
        stop_flag = true;
        this->start();

    }
    void addTuple(tuple_p tuple)
    {

    }
    static void* runThCap(void* args)
    {
        NDNthread *_this = (NDNthread*)args;
        /*int pid = syscall(SYS_gettid);
        string s = "taskset -cp ";

        //string cpu = "0,10 ";
        int mod = _this->id%20;
        s = s+ to_string(mod)+","+to_string(mod+10)+" ";

        s += to_string(pid);
        system(s.data());*/

        clock_t start, end;
        clock_t dstart, dend;
        while(_this->stop_flag)
        {
            tuple_p tuple;

            start = clock();
            while(LibPcapHelper::queuelist[_this->id].empty())
            {
                end = clock();
                if(end - start >= 100000000)
                {
                    _this->stop_flag = false;
                    LibPcapHelper::threadUsage[_this->id] = false;
                    break;
                }
            }
            if(_this->stop_flag == false)
                continue;
            LibPcapHelper::queuelist[_this->id].pop(tuple);




            string key = _this->ndnthhelper.build4TupleKey(tuple->key.src_ip, tuple->key.dst_ip,
                                                           tuple->key.src_port, tuple->key.dst_port);

            auto res = _this->sequenceTable.get(key);

            if (!res.second) {  //若不存在则将index即自增表的value设为1并插入；再存入缓存中
                tuple->index = 1;

                auto result_seq = _this->sequenceTable.save(key, tuple->index);

                if (!result_seq) {
                    cout << "插入失败" << endl;
                    continue;
                }

                auto dataPrefixUUID = _this->ndnthhelper.buildName(tuple->key.src_ip, tuple->key.dst_ip,
                                                                   tuple->key.src_port, tuple->key.dst_port, 4, tuple->index);


                _this->ndnthhelper.putDataToCache(dataPrefixUUID.first, tuple);




                auto prefixUUID = _this->ndnthhelper.buildName(tuple->key.src_ip, tuple->key.dst_ip,
                                                               tuple->key.src_port, tuple->key.dst_port, 3, 1);
                _this->ndnthhelper.expressInterest(prefixUUID.first);
            } else {//若存在则将index的值++，并查找悬而未决表
                if (!_this->sequenceTable.getAndIncreaseSequence(key, tuple)) {
                    cout << "获取自增序列失败" << endl;
                    continue;
                }

                auto dataPrefixUUID = _this->ndnthhelper.buildName(tuple->key.src_ip, tuple->key.dst_ip,
                                                                   tuple->key.src_port, tuple->key.dst_port, 4, tuple->index);



                _this->ndnthhelper.putDataToCache(dataPrefixUUID.first, tuple);

                //发送预请求兴趣包
                auto prePrefixUUID = _this->ndnthhelper.buildName(tuple->key.src_ip, tuple->key.dst_ip,
                                                                  tuple->key.src_port, tuple->key.dst_port, 3, tuple->index);

                _this->ndnthhelper.expressInterest(prePrefixUUID.first, true);

            }
            end = clock();
            cout<<"total time is "<<end-start<<"the data size is "<<tuple->ipSize<<endl;

        }
        _this->stop();
    }

    static void* ndnStart(void* args)
    {
        NDNthread *_this = (NDNthread*)args;
        _this->ndnthhelper.start();
    }
    void start()
    {
        int ret = pthread_create(&this->tid,NULL,runThCap,(void*)this);
        if(ret != 0){
            printf("query thread start error : error code = %d\n",ret) ;
        }
        int ret2 = pthread_create(&this->tid2,NULL,ndnStart,(void*)this);
        if(ret2 != 0){
            printf("query thread start error : error code = %d\n",ret) ;
        }
    }

    void stop()
    {
        this->stop_flag = false;
        pthread_join(this->tid, NULL);
    }

private:
    NDNHelper ndnthhelper;
    MapCacheHelper<int> sequenceTable;
    pthread_t tid, tid2;
    bool stop_flag;
    int id;

};






#endif //IP_NDN_STACK_CPP_LIBPCAPHELPER_H
