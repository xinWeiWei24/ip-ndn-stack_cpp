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
  /*  void
    asyncRead();

    void
    handleRead(const boost::system::error_code &error);

    void
    handleError(const std::string &errorMessage);
*/
private:
    PcapHelper mPcap;
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
    NDNthread(vector<string> ips, int id1,  string _dataPrefixUUID, string _prePrefixUUID, string _keyName)
    {

        this->id = id1;
        ndnthhelper.setRegisterIp(ips);
        stop_flag = true;
        this->start();
        dataPrefixUUID = _dataPrefixUUID;
        prePrefixUUID = _prePrefixUUID;
        keyName = _keyName;
        sequence = 0;

    }
    void addTuple(tuple_p tuple)
    {

    }

    struct combineTuple
    {
        uint8_t *it = NULL;
        int size = 0;
        ~combineTuple()
        {
            if(it)
                delete it;
        }
    };

    static void* runThCap(void* args)
    {
        NDNthread *_this = (NDNthread*)args;
/*        int pid = syscall(SYS_gettid);
        string s = "taskset -cp ";

        //string cpu = "0,10 ";
        int mod = _this->id%20;
        s = s+ to_string(mod)+","+to_string(mod+10)+" ";

        s += to_string(pid);
        system(s.data());
*/
        clock_t start, end;
        clock_t dstart, dend;
        while(_this->stop_flag) {
            tuple_p tuple;

            dstart = clock();
            dend = dstart;

            start = clock();
            end = start;

            while (LibPcapHelper::queuelist[_this->id].empty()) {
                dend = clock();
                if (dend - dstart >= 100000000) {
                    _this->stop_flag = false;
                    LibPcapHelper::threadUsage[_this->id] = false;
                    break;
                }
            }
            if (!_this->stop_flag)
                break;
            LibPcapHelper::queuelist[_this->id].pop(tuple);

            if (!_this->stop_flag)
                continue;

            start = clock();


            string datas(_this->dataPrefixUUID);
            datas += to_string(_this->sequence);
            _this->ndnthhelper.putDataToCache(datas, tuple);

            //发送预请求兴趣包
	    if(_this->sequence % 40 == 0){
            string pres(_this->prePrefixUUID);
            pres += to_string(_this->sequence);
            _this->ndnthhelper.expressInterest(pres, true);
	    }


            end = clock();
            //cout << "total time is " << end - start << "the data size is " << tuple->ipSize << endl;
            _this->sequence++;

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
    //MapCacheHelper<int> sequenceTable;
    int sequence;
    pthread_t tid, tid2;
    bool stop_flag;
    int id;
    string dataPrefixUUID;
    string prePrefixUUID;
    string keyName;

};






#endif //IP_NDN_STACK_CPP_LIBPCAPHELPER_H
