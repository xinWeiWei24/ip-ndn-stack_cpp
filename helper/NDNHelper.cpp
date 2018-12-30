//
// Created by mingj on 18-12-22.
//

#include "NDNHelper.h"

//前缀
const string NDNHelper::PREFIX_PRE_REQUEST = "/IP/pre";
const string NDNHelper::PREFIX_REQUEST_DATA = "/IP";
const string NDNHelper::PREFIX_TCP_PRE_REQUEST = "/IP/TCP/pre";
const string NDNHelper::PREFIX_TCP_REQUEST_DATA = "/IP/TCP";

//配置文件的键值
const string NDNHelper::KEY_CONFIG_REGISTER_IP = "registerIp";

NDNHelper::NDNHelper() : face("localhost") {
    cout << "NDN Helper constructor" << endl;
}

void NDNHelper::start() {
    cout << "registerIp: " << registerIp << endl;
    Name register_prefix1(NDNHelper::PREFIX_PRE_REQUEST + "/" + this->registerIp);
    Name register_prefix2(NDNHelper::PREFIX_REQUEST_DATA + "/" + this->registerIp);
    Name register_prefix3(NDNHelper::PREFIX_TCP_PRE_REQUEST + "/" + this->registerIp);
    Name register_prefix4(NDNHelper::PREFIX_TCP_REQUEST_DATA + "/" + this->registerIp);

    Interest::setDefaultCanBePrefix(true);
    try {
        face.setInterestFilter(InterestFilter(register_prefix1),
                               (const InterestCallback &) bind(&NDNHelper::onInterest, this, _1, _2, true, false),
                               (const RegisterPrefixFailureCallback &) bind(&NDNHelper::onRegisterFailed, this, _1));

        face.setInterestFilter(InterestFilter(register_prefix2),
                               (const InterestCallback &) bind(&NDNHelper::onInterest, this, _1, _2, false, false),
                               (const RegisterPrefixFailureCallback &) bind(&NDNHelper::onRegisterFailed, this, _1));

        face.setInterestFilter(InterestFilter(register_prefix3),
                               (const InterestCallback &) bind(&NDNHelper::onInterest, this, _1, _2, true, true),
                               (const RegisterPrefixFailureCallback &) bind(&NDNHelper::onRegisterFailed, this, _1));

        face.setInterestFilter(InterestFilter(register_prefix4),
                               (const InterestCallback &) bind(&NDNHelper::onInterest, this, _1, _2, false, true),
                               (const RegisterPrefixFailureCallback &) bind(&NDNHelper::onRegisterFailed, this, _1));
        face.processEvents();
    } catch (exception &e) {
        std::cerr << "ERROR: " << e.what() << std::endl;
    }
}


/**
 * 初始化与NDN交互模块
 * @param configFilePath 配置文件的路径
 * @return
 */
void NDNHelper::initNDN(string configFilePath) {
    JSONCPPHelper jsoncppHelper(configFilePath);
    this->registerIp = jsoncppHelper.getString(NDNHelper::KEY_CONFIG_REGISTER_IP);
}

/**
 * join thread
 */
void NDNHelper::join() {
    pthread_join(this->processEventThreadId, nullptr);
}


void NDNHelper::bindCacheHelper(MapCacheHelper<tuple_p> *cacheHelper) {
    this->cacheHelper = cacheHelper;
}


void NDNHelper::bindPendingInterestMap(MapCacheHelper<long> *pendingInterestMap) {
    this->pendingInterestMap = pendingInterestMap;
}

void NDNHelper::bindPrefixGuestTable(SetHelper<string> *prefixGuestTable) {
    this->prefixGuestTable = prefixGuestTable;
}

/**
 * 内部函数，处理onData事件
 * @param data
 */
void NDNHelper::dealOnData(const Data &data) {
    string name = data.getName().toUri();
    string pre = "/IP/pre/";
    if (name.find(pre, 0) != string::npos) {

    } else {        //正式拉取到包的回复
        vector<string> fileds;
        boost::split(fileds, name, boost::is_any_of("/"));
        this->rawSocketHelper.sendPacketTo(data.getContent().value(), data.getContent().value_size(), fileds[3]);
    }
}

/**
 * 内部函数，处理onInterest事件
 * @param prefix
 * @param interest
 * @param face
 * @param isPre 是否是预请求
 */
void NDNHelper::dealOnInterest(const Interest &interest, bool isPre, bool isTCP) {
    string interest_name = interest.getName().toUri();
    //string pre = "/IP/pre/";
    if (isPre) {
        if (isTCP) {
            string next_name = "/IP/TCP";
            vector<string> fileds;
            boost::split(fileds, interest_name, boost::is_any_of("/"));

            string sip = fileds[4];
            string dip = fileds[5];
            string uid = fileds[6];
            next_name.append("/" + dip);
            next_name.append("/" + sip);
            string guess_name = next_name;

            next_name.append("/" + uid);

            this->expressInterest(next_name, true);
            //发一个正式拉取的请求

			if (this->prefixGuestTable->find(next_name)) {
            	this->prefixGuestTable->erase(next_name);   //删除已经发送这条
			}

            vector<string> uuid_fileds;
            boost::split(uuid_fileds, uid, boost::is_any_of("-"));
            int num_of_sequence = boost::lexical_cast<int>(uuid_fileds[2]);

            guess_name.append("/" + uuid_fileds[0] + "-" + uuid_fileds[1] + "-");
            for (int i = 0; i < NUM_OF_GUEST; i++) {
                string g_name = guess_name;
                g_name.append(to_string(++num_of_sequence));
                if (this->prefixGuestTable->saveConcurrence(g_name)) {
                    this->expressInterest(g_name, true);
                }
            }
        } else {
            string next_name = "/IP";
            vector<string> fileds;
            boost::split(fileds, interest_name, boost::is_any_of("/"));

            string sip = fileds[3];
            string dip = fileds[4];
            string uid = fileds[5];
            next_name.append("/" + dip);
            next_name.append("/" + sip);
            next_name.append("/" + uid);

            //发一个正式拉取的请求
            this->expressInterest(next_name, false);
        }
    } else {
        vector<string> fileds;
        boost::split(fileds, interest_name, boost::is_any_of("/"));
        string uuid = fileds[4];
        auto res = cacheHelper->get(uuid);
        if (isTCP && !res.second) {     //是TCP的正式请求包，且未命中缓存
			this->pendingInterestMap->save(interest_name, this->getCurTime() + interest.getInterestLifetime().count());

        } else {
            if (!res.second) {
                cout << "没有找到uuid = " << uuid << "的数据包" << "(" << interest_name << ")" << endl;
                return;
            }
            tuple_p tuple1 = res.first;

            //删除
            cacheHelper->erase(uuid);

            Data data(interest_name);
            data.setContent(tuple1->pkt, tuple1->size);
            KeyChain_.sign(data);
            this->face.put(data);
        }
    }
}

void NDNHelper::onData(const Interest &interest, const Data &data) {
    this->dealOnData(data);
}

void NDNHelper::onNack(const Interest &, const lp::Nack &) {

}


void NDNHelper::onTimeout(const Interest &interest, bool isPre) {
    if (!isPre) {
        cout << "Timed out: " << interest.getName().toUri() << endl;
    }
}

void NDNHelper::onInterest(const InterestFilter &filter, const Interest &interest, bool isPre, bool isTCP) {
    this->dealOnInterest(interest, isPre, isTCP);
}


void NDNHelper::onRegisterFailed(const Name &prefix) {
    cout << "Register failed for prefix " << prefix.toUri() << endl;
}

void NDNHelper::expressInterest(string name, bool isPre) {
	Interest interest(name);
	interest.setInterestLifetime(2_s);	//兴趣报存活时间
	cout << "express interest: " << name << endl;
    this->face.expressInterest(interest, bind(&NDNHelper::onData, this, _1, _2),
                               bind(&NDNHelper::onNack, this, _1, _2), bind(&NDNHelper::onTimeout, this, _1, isPre));
}


void NDNHelper::putData(const string &name, const tuple_p tuple) {
    Data data(name);
    data.setContent(tuple->pkt, tuple->size);
    KeyChain_.sign(data);
    this->face.put(data);
}

/**
* 构造前缀
* @param sip
* @param dip
* @param sport
* @param dport
* @param type
*          type = 1    => /IP/pre
*          type = 2    => /IP
*          type = 3    => /IP/TCP/pre
*          type = 4    => /IP/TCP
* @return   <前缀，uuid>
*/
pair<string, string>  NDNHelper::buildName(uint32_t sip, uint32_t dip, uint16_t sport, uint16_t dport, int type, int seq,
                            string uid) {

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


    switch (type) {
        case 1:
            return make_pair(NDNHelper::PREFIX_PRE_REQUEST + "/" + sourceIP + "/" + dstIP + "/" + uid, uid);
        case 2:
            return make_pair(NDNHelper::PREFIX_REQUEST_DATA + "/" + sourceIP + "/" + dstIP + "/" + uid, uid);
        case 3:
            uid = sourcePort + "-" + dstIP +
                  "-" + to_string(seq);
            return make_pair(NDNHelper::PREFIX_TCP_PRE_REQUEST + "/" + sourceIP + "/" + dstIP + "/" + uid, uid);
        case 4:
            uid = sourcePort + "-" + dstIP +
                  "-" + to_string(seq);
            return make_pair(NDNHelper::PREFIX_TCP_REQUEST_DATA + "/" + sourceIP + "/" + dstIP + "/" + uid, uid);
        default:
            return make_pair("", "");
    }
}

string NDNHelper::build4TupleKey(uint32_t sip, uint32_t dip, uint16_t sport, uint16_t dport) {
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

long NDNHelper::getCurTime() {
    auto duration_in_ms = chrono::duration_cast<chrono::milliseconds>(
            chrono::system_clock::now()
            .time_since_epoch());
    return duration_in_ms.count();
}
