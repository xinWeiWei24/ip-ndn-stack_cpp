//
// Created by mingj on 18-12-18.
//
#include "NDNHelper.h"
#include "JSONCPPHelper.h"
#include "LibPcapHelper.h"
#include <execinfo.h>

using namespace std;
boost::lockfree::queue<tuple_p,boost::lockfree::capacity<40000>> LibPcapHelper::queuelist[10];
bool LibPcapHelper::threadUsage[MAX_THREAD_NUM] = {false};
void dealNDN(void *arg) {
    auto *ndnHelper = (NDNHelper *) arg;
    ndnHelper->start();
}

int main(int argc, char *argv[]) {

    try {
        NDNHelper ndnHelper;
        MapCacheHelper<tuple_p> cacheHelper;
        MapCacheHelper<long> pendingInterestMap;
        MapCacheHelper<int> sequenceTable;
        SetHelper<string> prefixRequestTable;
        LibPcapHelper libPcapHelper(argv[1]);

        ndnHelper.bindCacheHelper(&cacheHelper);
        ndnHelper.bindPendingInterestMap(&pendingInterestMap);
        ndnHelper.bindPrefixGuestTable(&prefixRequestTable);
        libPcapHelper.bindCacheHelper(&cacheHelper);

        libPcapHelper.bindPendingInterestTable(&pendingInterestMap);
        libPcapHelper.bindSequenceTable(&sequenceTable);
        libPcapHelper.bindNDNHelper(&ndnHelper);


        ndnHelper.initNDN(argv[1]);

        //在另一个线程处理NDN事件
        boost::thread t(bind(&dealNDN, &ndnHelper));

        //开始抓包
        libPcapHelper.start();

        t.join();
        ndnHelper.join();
        libPcapHelper.close();

    } catch (std::exception &e) {
        cerr << e.what() << endl;
    }


    return 0;
}

