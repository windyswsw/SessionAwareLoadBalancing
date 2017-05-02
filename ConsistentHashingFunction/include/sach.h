#pragma once

#include <string>
#include <vector>
#include <map>
#include <set>
#include <cstdint>
#include <exception>

#include <boost/unordered_map.hpp>
#include <boost/chrono.hpp>
#include <boost/thread.hpp>
#include <boost/asio.hpp>

namespace sach {

typedef uint32_t ip_t;
typedef uint16_t port_t;
typedef uint64_t timestamp_t;
typedef int16_t tag_t;

struct SocketInfo {
	ip_t srcIp;
	ip_t destIp;
	port_t srcPort;
	port_t destPort;

	SocketInfo() :
			srcIp(0), destIp(0), srcPort(0), destPort(0) {
	}
	SocketInfo(ip_t sIp, port_t sPort, ip_t dIp, port_t dPort) :
			srcIp(sIp), destIp(dIp), srcPort(sPort), destPort(dPort) {
	}
	SocketInfo(const SocketInfo &sock) :
			srcIp(sock.srcIp), destIp(sock.destIp), srcPort(sock.srcPort), destPort(
					sock.destPort) {
	}
};

typedef SocketInfo SessionKey;

bool operator==(const SessionKey &key1, const SessionKey &key2);
size_t hash_value(const SessionKey &key);

struct Packet {
	SocketInfo socket;
	timestamp_t timestamp;	///< timestamp of the packet
	bool inbound;	///< inbound/outbound flag
	tag_t existingTag;
	void * pointer;		///< pointer to the actual packet

	Packet() : socket(), timestamp(0), inbound(true), existingTag(0), pointer(NULL) {
	}

	Packet(ip_t sIp, port_t sPt, ip_t dIp, port_t dPt, timestamp_t ts, bool dir, tag_t tag) :
			socket(sIp, sPt, dIp, dPt), timestamp(ts), inbound(dir), existingTag(tag), pointer(
			NULL) {
	}
};

struct RoutingTagPair {
	tag_t inboundTag;
	tag_t outboundTag;

	RoutingTagPair() :
			inboundTag(0), outboundTag(0) {
	}
	RoutingTagPair(tag_t it, tag_t ot) :
			inboundTag(it), outboundTag(ot) {
	}
};

bool operator==(const RoutingTagPair &tp1, const RoutingTagPair &tp2);
bool operator<(const RoutingTagPair &tp1, const RoutingTagPair &tp2);
size_t hash_value(const RoutingTagPair &tp);

typedef RoutingTagPair InstanceID;

struct SessionStatus {
	timestamp_t lastUpdate;	///< the timestamp of the last packet belonging to this session
	InstanceID instance;	///< the assigned network function instance

	SessionStatus() :
			lastUpdate(0), instance() {
	}

	SessionStatus(timestamp_t t) :
			lastUpdate(t), instance() {
	}
};

typedef boost::unordered_map<SessionKey, SessionStatus> SessionMap;

///
/// The session manager maintains a list of known sessions:
/// * a session identified by the source IP/port + destination IP/port
/// * a session is considered to be active if there is a seen packet within the last tau time window
/// * in the current version inactive sessions are removed lazily
/// * sessions are stored in a four-level hashtable <inIp, <outIp, <inPort, <outPort, ts>>>>
///
class SessionManager {
private:
	timestamp_t sessionTau;	///< the time window for deciding whether a session is active
	SessionMap sessions;
public:
	SessionManager() :
			//sessionTau(180000) {
                        sessionTau(5000) {
	}
	/// returns true iff a new session is created.
	/// this method will update the session timestamp to be "ts"
	bool createOrRefreshSession(SessionKey &key, timestamp_t ts);
	bool isInActiveSession(Packet &p);

	/// returns true iff the session key exists
	/// No effect (in setting/getting) if session key doesn't exist
	bool assignInstance(SessionKey &key, InstanceID &inst);
	bool retrieveInstance(SessionKey &key, InstanceID &inst);

	void setSessionTau(timestamp_t tau) {
		sessionTau = tau;
	}

	timestamp_t getSessionTau() {
		return sessionTau;
	}

	SessionKey getPacketSessionKey(Packet &p);
};

class LoadMonitor {
private:
	boost::unordered_map<InstanceID, std::pair<size_t, size_t>> counters;
	std::map<InstanceID, std::pair<double, double>> statistics;
	double timeWindow;
	boost::chrono::high_resolution_clock::time_point lastTime;///< in milli-seconds

	void updateTrafficLoads(double durationInSeconds);
	void resetCounters();
public:
	LoadMonitor() :
			timeWindow(1000.0) {
		lastTime = boost::chrono::high_resolution_clock::now();
	}

	void setTimeWindow(double millisecs) {
		timeWindow = millisecs;
	}

	double getTimeWindow() {
		return timeWindow;
	}

	/// no effects if the instance id already exists
	void addInstance(InstanceID &inst);
	/// no effects if the instance id doesn't exist
	void removeInstance(InstanceID &inst);

	/// the counter won't be updated if the instance id doesn't exist
	/// however, statistics update may be triggered by the timer
	bool incrementCounter(InstanceID &inst, bool inbound);

	void getTrafficLoads(
			std::map<InstanceID, std::pair<double, double>> &stats);

	bool hasInstance(InstanceID &inst) {
		return counters.find(inst) != counters.end();
	}
};

class SessionAwareConsistentHashing {
private:
	std::vector<InstanceID> buckets;

	SessionManager &sesManager;
public:
	SessionAwareConsistentHashing(SessionManager &sMan) :
			sesManager(sMan) {
	}

	/// create the buckets array according to instance slots
	void updateBuckets(unsigned int seed, std::map<InstanceID, size_t> &slots);

	/// compute the target instance with internal update
	InstanceID mapPacketToInstance(Packet &p);
};

class SachException: public std::exception {
private:
	std::string message;
public:
	SachException(std::string msg) :
			message(msg) {
	}

	virtual const char* what() const throw () {
		return message.c_str();
	}
};

class LoadBalancer {
private:
	bool isMaster;///< true <-> master (left balancer); false <-> slave (right balancer)
	std::string slaveIp;
	std::string slavePort;
	std::string controlPort;

	boost::thread ctlTh;
	boost::thread rmiTh;

	std::set<InstanceID> instances;
	boost::unordered_map<InstanceID, boost::chrono::high_resolution_clock::time_point> coolingDownInstances;
	std::map<InstanceID, double> loadAssignments;
	size_t totalSlots = 1000;

	SessionManager sesManager;
	LoadMonitor loadMonitor;
	SessionAwareConsistentHashing hashing;

	bool rmiRequestGetStatistics(
			std::map<InstanceID, std::pair<double, double>> &rmStats);
	bool rmiRequestUpdateHashFunction(unsigned int seed,
			std::map<InstanceID, size_t> &slots);
	bool rmiRequestAddInstance(InstanceID &inst);
	bool rmiRequestRemoveInstance(InstanceID &inst);

	std::string rmiRespondGetStatistics();
	std::string rmiRespondUpdateHashFunction(unsigned int seed,
			std::map<InstanceID, size_t> &slots);
	std::string rmiRespondAddInstance(InstanceID &inst);
	std::string rmiRespondRemoveInstance(InstanceID &inst);

	std::string readTcpRequest(boost::asio::ip::tcp::socket &sock);
	std::string readTcpReply(boost::asio::ip::tcp::socket &sock);

	std::string tcpRequestRespond(std::string reqStr);  ///< for the master
	std::string handleMasterRequest(std::string reqStr);	///< for the slave
	std::string handleControlCommand(std::string reqStr);	///< for the master

	void runRmiServer();	/// the rmi server, serving the master
	void runCtlServer();	/// the control thread (serving the network manager)

	void collectHistoricalLoads(double &totalLoad,
			std::map<InstanceID, double> &loads);
	void balanceLoadsForNewInstance(InstanceID &inst);
	void balanceLoadsForRemovedInstance(InstanceID &inst);
	/// pre: there is more than one instance
	void balanceLoadsForExistingInstances();

	void normaliseProbabilities(std::map<InstanceID, double> &probs);
	void updateLoadAssignments(std::map<InstanceID, double> &loads);
public:
	LoadBalancer(std::string cPort, std::string sIp, std::string sPort);
	LoadBalancer(std::string sPort);

        //WR LB
        LoadBalancer(std::string cPort, std::string sIp, std::string sPort, timestamp_t tauNew);
        LoadBalancer(std::string sPort, timestamp_t tauNew);

	tag_t packetToInstance(Packet &p);
	void addInstance(InstanceID &inst);
	void removeInstanceWithCoolDown(InstanceID &inst);

	/// return true if and only if the instance is not removed or
	/// still in the cool down phase.
	bool isActive(InstanceID &inst);
};

}
;
