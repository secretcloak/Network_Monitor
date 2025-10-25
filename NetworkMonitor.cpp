#include <arpa/inet.h>
#include <errno.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <net/if.h>
#include <unistd.h>

#include <atomic>
#include <chrono>
#include <cstring>
#include <functional>
#include <iomanip>
#include <iostream>
#include <memory>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>
#include <vector>
#include <condition_variable>

using namespace std::chrono;
using Clock = std::chrono::system_clock;

//Timestamp helper
static std::string now_str() {
    auto now = Clock::now();
    auto itt = Clock::to_time_t(now);
    std::tm tm;
    localtime_r(&itt, &tm);
    char buf[64];
    strftime(buf, sizeof(buf), "%F %T", &tm);
    auto ms = duration_cast<milliseconds>(now.time_since_epoch()) % 1000;
    char out[80];
    snprintf(out, sizeof(out), "%s.%03lld", buf, (long long)ms.count());
    return std::string(out);
}

//Custom linked-node container utilities
template<typename T>
struct Node {
    T val;
    Node* next;
    Node(const T& v) : val(v), next(nullptr) {}
};

//Stack<T>
template<typename T>
class Stack {
private:
    Node<T>* head;
    std::mutex m;
public:
    Stack(): head(nullptr) {}
    ~Stack() {
        while (head) { Node<T>* tmp = head; head = head->next; delete tmp; }
    }
    void push(const T& v) {
        std::lock_guard<std::mutex> lg(m);
        Node<T>* n = new Node<T>(v);
        n->next = head;
        head = n;
    }
    bool empty() {
        std::lock_guard<std::mutex> lg(m);
        return head == nullptr;
    }
    T pop() {
        std::lock_guard<std::mutex> lg(m);
        if (!head) throw std::runtime_error("Stack underflow");
        Node<T>* n = head;
        head = head->next;
        T v = n->val;
        delete n;
        return v;
    }
    T top() {
        std::lock_guard<std::mutex> lg(m);
        if (!head) throw std::runtime_error("Stack empty");
        return head->val;
    }
    // Return a snapshot of elements from top->bottom for inspection.
    std::vector<T> snapshot() {
        std::lock_guard<std::mutex> lg(m);
        std::vector<T> out;
        Node<T>* cur = head;
        while (cur) { out.push_back(cur->val); cur = cur->next; }
        return out;
    }
};

//Queue<T>
template<typename T>
class Queue {
private:
    Node<T>* head;
    Node<T>* tail;
    std::mutex m;
public:
    Queue(): head(nullptr), tail(nullptr) {}
    ~Queue() {
        while (head) { Node<T>* tmp = head; head = head->next; delete tmp; }
    }
    void enqueue(const T& v) {
        std::lock_guard<std::mutex> lg(m);
        Node<T>* n = new Node<T>(v);
        if (!tail) { head = tail = n; return; }
        tail->next = n;
        tail = n;
    }
    bool try_dequeue(T& out) {
        std::lock_guard<std::mutex> lg(m);
        if (!head) return false;
        Node<T>* n = head;
        head = head->next;
        if (!head) tail = nullptr;
        out = n->val;
        delete n;
        return true;
    }
    bool empty() {
        std::lock_guard<std::mutex> lg(m);
        return head == nullptr;
    }
    bool peek(T& out) {
        std::lock_guard<std::mutex> lg(m);
        if (!head) return false;
        out = head->val;
        return true;
    }
    // Non-atomic snapshot useful for display
    std::vector<T> snapshot() {
        std::lock_guard<std::mutex> lg(m);
        std::vector<T> v;
        Node<T>* cur = head;
        while (cur) { v.push_back(cur->val); cur = cur->next; }
        return v;
    }
};

// Packet representation

struct Packet {
    uint64_t id;
    std::string timestamp;
    std::vector<uint8_t> buffer;
    std::string src_ip;
    std::string dst_ip;

    // Tracks how many replay attempts have been made for this packet.
    int replay_attempts = 0;

    Packet() : id(0), timestamp(""), buffer(), src_ip(), dst_ip() {}
    size_t size() const { return buffer.size(); }
};

// Global state, queues and configuration

std::atomic<uint64_t> global_packet_id{0};

 // newly captured frames awaiting dissection
Queue<Packet*> capturedQueue;
 // frames ready for filtering
Queue<Packet*> dissectedQueue;
    // filtered frames to be replayed
Queue<Packet*> replayQueue;
    // frames that failed replay and are retained for retries
Queue<Packet*> backupQueue;

std::atomic<bool> stop_all{false};

const size_t MAX_MTU = 1500;
const size_t OVERSIZE_THRESHOLD = 5;
std::atomic<size_t> oversize_count{0};

// IP address formatting helpers

static std::string ipv4_to_string(const void* addr) {
    char buf[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, addr, buf, sizeof(buf));
    return std::string(buf);
}
static std::string ipv6_to_string(const void* addr) {
    char buf[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, addr, buf, sizeof(buf));
    return std::string(buf);
}

//Packet parsing functions (stack-oriented)

//Parse a raw Ethernet header from the buffer at the beginning

bool parse_ethernet(const std::vector<uint8_t>& buf, Stack<std::string>& layerStack, size_t& offset, uint16_t& ethertype) {
    if (buf.size() < 14) return false;
    // Ethernet header layout: dst(6) | src(6) | type(2)
    ethertype = (buf[12] << 8) | buf[13];
    std::ostringstream ss;
    ss << "Ethernet: type=0x" << std::hex << ethertype;
    layerStack.push(ss.str());
    offset = 14;
    return true;
}

//Parse an IPv4 header at the current offset, push a description

bool parse_ipv4(const std::vector<uint8_t>& buf, Stack<std::string>& layerStack, size_t& offset, uint8_t& protocol, std::string& src, std::string& dst) {
    if (buf.size() < offset + sizeof(struct iphdr)) return false;
    struct iphdr ih;
    std::memcpy(&ih, buf.data() + offset, sizeof(struct iphdr));
    size_t ihl = ih.ihl * 4;
    if (buf.size() < offset + ihl) return false;
    struct in_addr saddr, daddr;
    saddr.s_addr = ih.saddr;
    daddr.s_addr = ih.daddr;
    src = ipv4_to_string(&saddr);
    dst = ipv4_to_string(&daddr);
    protocol = ih.protocol;
    std::ostringstream ss;
    ss << "IPv4: src=" << src << " dst=" << dst << " proto=" << (int)protocol;
    layerStack.push(ss.str());
    offset += ihl;
    return true;
}

//Parse an IPv6 header at the current offset, push a description

bool parse_ipv6(const std::vector<uint8_t>& buf, Stack<std::string>& layerStack, size_t& offset, uint8_t& next_header, std::string& src, std::string& dst) {
    if (buf.size() < offset + sizeof(struct ip6_hdr)) return false;
    struct ip6_hdr ip6;
    std::memcpy(&ip6, buf.data() + offset, sizeof(struct ip6_hdr));
    next_header = ip6.ip6_nxt;
    src = ipv6_to_string(&ip6.ip6_src);
    dst = ipv6_to_string(&ip6.ip6_dst);
    std::ostringstream ss;
    ss << "IPv6: src=" << src << " dst=" << dst << " nxt=" << (int)next_header;
    layerStack.push(ss.str());
    offset += sizeof(struct ip6_hdr);
    return true;
}

// Parse a TCP header at the current offset and push a description

bool parse_tcp(const std::vector<uint8_t>& buf, Stack<std::string>& layerStack, size_t& offset) {
    if (buf.size() < offset + sizeof(struct tcphdr)) return false;
    struct tcphdr th;
    std::memcpy(&th, buf.data() + offset, sizeof(struct tcphdr));
    uint16_t srcp = ntohs(th.source);
    uint16_t dstp = ntohs(th.dest);
    std::ostringstream ss;
    ss << "TCP: src_port=" << srcp << " dst_port=" << dstp;
    layerStack.push(ss.str());
    uint8_t data_offset = th.th_off * 4;
    offset += data_offset;
    return true;
}

//Parse a UDP header at the current offset and push a description

bool parse_udp(const std::vector<uint8_t>& buf, Stack<std::string>& layerStack, size_t& offset) {
    if (buf.size() < offset + sizeof(struct udphdr)) return false;
    struct udphdr uh;
    std::memcpy(&uh, buf.data() + offset, sizeof(struct udphdr));
    uint16_t srcp = ntohs(uh.source);
    uint16_t dstp = ntohs(uh.dest);
    std::ostringstream ss;
    ss << "UDP: src_port=" << srcp << " dst_port=" << dstp;
    layerStack.push(ss.str());
    offset += sizeof(struct udphdr);
    return true;
}

// High-level dissection routine
void dissect_packet(Packet* p) {
    Stack<std::string> layerStack;
    size_t offset = 0;
    uint16_t ethertype = 0;

    if (!parse_ethernet(p->buffer, layerStack, offset, ethertype)) {
        layerStack.push("Ethernet: parse_error");
    } 
    // IPv4
    else {
        if (ethertype == 0x0800) { 
            uint8_t proto = 0;
            std::string src, dst;
            if (!parse_ipv4(p->buffer, layerStack, offset, proto, src, dst)) {
                layerStack.push("IPv4: parse_error");
            } else {
                p->src_ip = src;
                p->dst_ip = dst;
                if (proto == IPPROTO_TCP) {
                    if (!parse_tcp(p->buffer, layerStack, offset)) layerStack.push("TCP: parse_error");
                } else if (proto == IPPROTO_UDP) {
                    if (!parse_udp(p->buffer, layerStack, offset)) layerStack.push("UDP: parse_error");
                } else {
                    std::ostringstream ss; ss << "IPv4: other_proto=" << (int)proto;
                    layerStack.push(ss.str());
                }
            }
        } 
        // IPv6
        else if (ethertype == 0x86DD) {
            uint8_t nxt = 0;
            std::string src, dst;
            if (!parse_ipv6(p->buffer, layerStack, offset, nxt, src, dst)) {
                layerStack.push("IPv6: parse_error");
            } else {
                p->src_ip = src;
                p->dst_ip = dst;
                if (nxt == IPPROTO_TCP) {
                    if (!parse_tcp(p->buffer, layerStack, offset)) layerStack.push("TCP: parse_error");
                } else if (nxt == IPPROTO_UDP) {
                    if (!parse_udp(p->buffer, layerStack, offset)) layerStack.push("UDP: parse_error");
                } else {
                    std::ostringstream ss; ss << "IPv6: other_nxt=" << (int)nxt;
                    layerStack.push(ss.str());
                }
            }
        } else {
            std::ostringstream ss; ss << "Ethernet: unknown_ethertype=0x" << std::hex << ethertype;
            layerStack.push(ss.str());
        }
    }

    // Convert stack snapshot into a readable summary 
    std::vector<std::string> layers = layerStack.snapshot();
    std::ostringstream summary;
    for (auto &s : layers) {
        summary << s << " | ";
    }
    dissectedQueue.enqueue(p);

    // Log minimal summary for console visibility.
    std::cout << "[" << now_str() << "] Dissected packet ID=" << p->id
              << " src=" << p->src_ip << " dst=" << p->dst_ip
              << " layers=(" << layers.size() << ") " << std::endl;
}

// Raw socket creation and binding helper
int create_raw_socket_bind(const std::string& iface) {
    int sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sockfd < 0) {
        std::cerr << "socket() failed: " << strerror(errno) << std::endl;
        return -1;
    }
    // Resolve interface index using ioctl(SIOCGIFINDEX)
    struct ifreq ifr;
    std::strncpy(ifr.ifr_name, iface.c_str(), IFNAMSIZ-1);
    if (ioctl(sockfd, SIOCGIFINDEX, &ifr) == -1) {
        std::cerr << "ioctl(SIOCGIFINDEX) failed: " << strerror(errno) << std::endl;
        close(sockfd);
        return -1;
    }
    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = ifr.ifr_ifindex;
    sll.sll_protocol = htons(ETH_P_ALL);
    if (bind(sockfd, (struct sockaddr*)&sll, sizeof(sll)) < 0) {
        std::cerr << "bind() failed: " << strerror(errno) << std::endl;
        close(sockfd);
        return -1;
    }
    return sockfd;
}

// Capture thread
void capture_thread_fn(const std::string& iface) {
    int sockfd = create_raw_socket_bind(iface);
    if (sockfd < 0) {
        std::cerr << "Capture thread exiting due to socket setup failure.\n";
        stop_all = true;
        return;
    }
    std::cout << "Capture thread started on interface: " << iface << std::endl;

    const size_t BUFSZ = 65536;
    std::vector<uint8_t> buf(BUFSZ);

    while (!stop_all) {
        ssize_t n = recvfrom(sockfd, buf.data(), (size_t)BUFSZ, 0, nullptr, nullptr);
        if (n < 0) {
            if (errno == EINTR) continue; // interrupted by signal; try again
            std::cerr << "recvfrom error: " << strerror(errno) << std::endl;
            break;
        }

        // Allocate packet and copy bytes
        Packet* p = new Packet();
        p->id = ++global_packet_id;
        p->timestamp = now_str();
        p->buffer.assign(buf.begin(), buf.begin() + n);

        // Update oversize counter for frames exceeding MTU
        if (p->size() > MAX_MTU) {
            size_t cur = ++oversize_count;
            std::cout << "[" << now_str() << "] Oversized packet observed (size=" << p->size() << ") count=" << cur << std::endl;
        }

        // Enqueue for dissection stage
        capturedQueue.enqueue(p);
    }

    close(sockfd);
    std::cout << "Capture thread exiting.\n";
}

// Dissection worker thread
void dissection_thread_fn() {
    std::cout << "Dissection thread started.\n";
    while (!stop_all) {
        Packet* p = nullptr;
        if (!capturedQueue.try_dequeue(p)) {
            // No available packet; sleep briefly to reduce CPU usage
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
            continue;
        }
        if (!p) continue;

        // If many oversized packets have been observed, we avoid heavy parsing.
        if (p->size() > MAX_MTU && oversize_count.load() > OVERSIZE_THRESHOLD) {
            std::cout << "[" << now_str() << "] Skipping heavy dissection for oversized packet ID=" << p->id << " size=" << p->size() << std::endl;
            dissectedQueue.enqueue(p);
            continue;
        }

        // Perform parsing using the stack-based dissection routine.
        dissect_packet(p);
    }
    std::cout << "Dissection thread exiting.\n";
}

// Filtering configuration structure
struct FilterConfig {
    std::string src_ip;
    std::string dst_ip;
    size_t oversize_allowed_before_skip = OVERSIZE_THRESHOLD;
};

// Filtering worker thread
void filtering_thread_fn(const FilterConfig& cfg) {
    std::cout << "Filtering thread started. Filtering: src=" << cfg.src_ip << " dst=" << cfg.dst_ip << "\n";
    while (!stop_all) {
        Packet* p = nullptr;
        if (!dissectedQueue.try_dequeue(p)) {
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
            continue;
        }
        if (!p) continue;

        // Skip oversized frames if policy dictates.
        if (p->size() > MAX_MTU && oversize_count.load() > cfg.oversize_allowed_before_skip) {
            std::cout << "[" << now_str() << "] Filtering: skipping oversized packet ID=" << p->id << std::endl;
            delete p;
            continue;
        }

        // Apply IP-based filtering; empty filter fields act as wildcards.
        bool match = true;
        if (!cfg.src_ip.empty() && p->src_ip != cfg.src_ip) match = false;
        if (!cfg.dst_ip.empty() && p->dst_ip != cfg.dst_ip) match = false;

        if (match) {
            replayQueue.enqueue(p);
            double delay_ms = double(p->size()) / 1000.0;
            std::cout << "[" << now_str() << "] Filtered packet ID=" << p->id
                      << " src=" << p->src_ip << " dst=" << p->dst_ip
                      << " size=" << p->size() << " estimated_delay_ms=" << std::fixed << std::setprecision(3) << delay_ms
                      << std::endl;
        } 
        else {
            // Not matched; free memory
            delete p;
        }
    }
    std::cout << "Filtering thread exiting.\n";
}

// Create a raw send socket used by replay and backup threads.
int create_raw_send_socket(const std::string& iface) {
    int sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sockfd < 0) {
        std::cerr << "send socket() failed: " << strerror(errno) << std::endl;
        return -1;
    }
    return sockfd;
}

// Replay worker thread
void replay_thread_fn(const std::string& iface) {
    int send_sock = create_raw_send_socket(iface);
    if (send_sock < 0) {
        std::cerr << "Replay thread cannot create send socket; replay disabled.\n";
        // If socket creation fails, move queued packets to backup for visibility/handling.
        while (!stop_all) {
            Packet* p = nullptr;
            if (replayQueue.try_dequeue(p)) {
                p->replay_attempts++;
                if (p->replay_attempts > 2) {
                    std::cout << "[" << now_str() << "] Replay failed irrecoverably for ID=" << p->id << " moving to backup\n";
                    backupQueue.enqueue(p);
                } else {
                    backupQueue.enqueue(p);
                }
            } else {
                std::this_thread::sleep_for(std::chrono::milliseconds(50));
            }
        }
        return;
    }

    // Resolve interface index for the destination sockaddr_ll used by sendto.
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    std::strncpy(ifr.ifr_name, iface.c_str(), IFNAMSIZ-1);
    if (ioctl(send_sock, SIOCGIFINDEX, &ifr) == -1) {
        std::cerr << "ioctl(SIOCGIFINDEX) failed in replay: " << strerror(errno) << std::endl;
    }
    struct sockaddr_ll dest;
    memset(&dest, 0, sizeof(dest));
    dest.sll_family = AF_PACKET;
    dest.sll_ifindex = ifr.ifr_ifindex;
    dest.sll_halen = ETH_ALEN;

    std::cout << "Replay thread started (send socket ok).\n";

    while (!stop_all) {
        Packet* p = nullptr;
        if (!replayQueue.try_dequeue(p)) {
            std::this_thread::sleep_for(std::chrono::milliseconds(20));
            continue;
        }
        if (!p) continue;

        // Simulate scheduling delay proportional to frame size.
        int delay_ms = int(p->size() / 1000.0);
        if (delay_ms <= 0) delay_ms = 1;
        std::this_thread::sleep_for(std::chrono::milliseconds(delay_ms));

        ssize_t sent = sendto(send_sock, p->buffer.data(), p->buffer.size(), 0,
                              (struct sockaddr*)&dest, sizeof(dest));
        if (sent == (ssize_t)p->buffer.size()) {
            std::cout << "[" << now_str() << "] Replayed packet ID=" << p->id << " size=" << p->size()
                      << " delay_ms=" << delay_ms << std::endl;
            // On success, free the packet memory.
            delete p;
        } else {
            p->replay_attempts++;
            std::cerr << "[" << now_str() << "] Replay error for packet ID=" << p->id
                      << " attempt=" << p->replay_attempts << " errno=" << errno << " msg=" << strerror(errno) << std::endl;
            if (p->replay_attempts > 2) {
                std::cerr << "[" << now_str() << "] Moving packet ID=" << p->id << " to backup after retries\n";
                backupQueue.enqueue(p);
            } else {
                // Re-enqueue for another retry attempt.
                replayQueue.enqueue(p);
            }
        }
    }

    close(send_sock);
    std::cout << "Replay thread exiting.\n";
}

// Backup handler thread
void backup_thread_fn(const std::string& iface) {
    std::cout << "Backup thread started.\n";
    int send_sock = create_raw_send_socket(iface);
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    std::strncpy(ifr.ifr_name, iface.c_str(), IFNAMSIZ-1);
    if (ioctl(send_sock, SIOCGIFINDEX, &ifr) == -1) {
    
    }
    struct sockaddr_ll dest;
    memset(&dest, 0, sizeof(dest));
    dest.sll_family = AF_PACKET;
    dest.sll_ifindex = ifr.ifr_ifindex;
    dest.sll_halen = ETH_ALEN;

    while (!stop_all) {
        Packet* p = nullptr;
        if (!backupQueue.try_dequeue(p)) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            continue;
        }
        if (!p) continue;

        // If we have already tried 3+ times, give up to avoid endless retries.
        if (p->replay_attempts >= 3) {
            std::cerr << "[" << now_str() << "] Backup: Giving up on packet ID=" << p->id << " after " << p->replay_attempts << " attempts\n";
            delete p;
            continue;
        }

        // Try a final send attempt.
        ssize_t sent = sendto(send_sock, p->buffer.data(), p->buffer.size(), 0,
                              (struct sockaddr*)&dest, sizeof(dest));
        if (sent == (ssize_t)p->buffer.size()) {
            std::cout << "[" << now_str() << "] Backup: successfully replayed packet ID=" << p->id << std::endl;
            delete p;
        } else {
            p->replay_attempts++;
            std::cerr << "[" << now_str() << "] Backup send failed for ID=" << p->id << " attempt=" << p->replay_attempts << std::endl;
            if (p->replay_attempts >= 3) {
                std::cerr << "[" << now_str() << "] Backup: dropping packet ID=" << p->id << " after retries\n";
                delete p;
            } else {
                // Re-queue for another eventual retry.
                backupQueue.enqueue(p);
            }
        }
    }
    if (send_sock >= 0) close(send_sock);
    std::cout << "Backup thread exiting.\n";
}


void display_captured() {
    auto items = capturedQueue.snapshot();
    std::cout << "---- Captured Queue (" << items.size() << ") ----\n";
    for (auto p : items) {
        if (p) {
            std::cout << "ID=" << p->id << " time=" << p->timestamp
                      << " size=" << p->size() << " src=" << p->src_ip << " dst=" << p->dst_ip << "\n";
        }
    }
}

void display_replay_queue() {
    auto items = replayQueue.snapshot();
    std::cout << "---- Replay Queue (" << items.size() << ") ----\n";
    for (auto p : items) {
        if (p) {
            double delay = double(p->size()) / 1000.0;
            std::cout << "ID=" << p->id << " size=" << p->size() << " delay_ms=" << delay << " attempts=" << p->replay_attempts << "\n";
        }
    }
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: sudo " << argv[0] << " <network_interface>\n";
        return 1;
    }
    std::string iface = argv[1];

    std::cout << "Network Monitor Starting. Interface: " << iface << "\n";
    std::cout << "Assumptions: run as root, Linux, custom stacks and queues used for parsing and packet management.\n";
    std::cout << "Demo will run capture for 60 seconds.\n";

    // Filtering configuration
    FilterConfig cfg;
    cfg.src_ip = ""; 
    cfg.dst_ip = ""; 
    cfg.oversize_allowed_before_skip = OVERSIZE_THRESHOLD;

    // Starts pipeline threads
    std::thread capThread(capture_thread_fn, iface);
    std::thread disThread(dissection_thread_fn);
    std::thread filtThread(filtering_thread_fn, cfg);
    std::thread replayThread(replay_thread_fn, iface);
    std::thread backupThread(backup_thread_fn, iface);

    // Demonstration window
    auto demoStart = Clock::now();
    auto demoDuration = std::chrono::seconds(60);
    while (Clock::now() - demoStart < demoDuration) {
        std::this_thread::sleep_for(std::chrono::seconds(5));
        std::cout << "----- Status snapshot at " << now_str() << " -----\n";
        display_replay_queue();
    }

    // Signal threads to stop and join 
    std::cout << "Demo time completed. Stopping threads...\n";
    stop_all = true;

    if (capThread.joinable()) capThread.join();
    if (disThread.joinable()) disThread.join();
    if (filtThread.joinable()) filtThread.join();
    if (replayThread.joinable()) replayThread.join();
    if (backupThread.joinable()) backupThread.join();

    std::cout << "All threads stopped. Exiting.\n";
    return 0;
}

