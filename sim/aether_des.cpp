#include <iostream>
#include <vector>
#include <random>
#include <queue>
#include <algorithm>
#include <chrono>

using namespace std;

const int NUM_ZONES = 256;
const int ZONES_PER_NODE = 16;
const int DEGREE = 6;
const int FANOUT = 4;
const int BASE_LATENCY_MS = 50;
const int JITTER_MS = 50;

struct Event {
    int time;
    int type; // 0=STEM, 1=FLUFF, 2=GOSSIP
    int node_id;
    int zone_id;
    int packet_id;
    int author_id;
    bool operator>(const Event& other) const { return time > other.time; }
};

struct Node {
    bool is_online = true;
    uint8_t zones[ZONES_PER_NODE];
    uint8_t mesh_counts[ZONES_PER_NODE] = {0};
    int mesh[ZONES_PER_NODE][10]; 
    int seen_packet_id = -1; 
};

struct Metrics {
    int deliveries = 0;
    long long sum_latency = 0;
    int max_latency = 0;
    long long total_gossip = 0;
};

int main(int argc, char** argv) {
    int NUM_NODES = 1000000;
    if (argc > 1) NUM_NODES = atoi(argv[1]);
    
    double CHURN_RATE = 0.2;
    if (argc > 2) CHURN_RATE = atof(argv[2]);

    cout << "\n========================================================" << endl;
    cout << "   AETHER Web-Lite C++ Global P2P Simulator" << endl;
    cout << "========================================================" << endl;
    cout << "Nodes: " << NUM_NODES << " | Zones: 256 | Degree: 6 | Fanout: 4 | Churn: " << CHURN_RATE*100 << "%" << endl;
    
    auto t1 = chrono::steady_clock::now();
    
    vector<Node>* nodes = new vector<Node>(NUM_NODES);
    vector<vector<int>> zoneMap(NUM_ZONES);
    
    mt19937 gen(42);
    
    cout << "\n[Phase] Initializing Zones (Bootstrap)... ";
    vector<uint8_t> all_z(NUM_ZONES);
    for(int z=0; z<NUM_ZONES; z++) all_z[z] = z;
    
    for (int i = 0; i < NUM_NODES; ++i) {
        shuffle(all_z.begin(), all_z.end(), gen);
        for (int j = 0; j < ZONES_PER_NODE; ++j) {
            (*nodes)[i].zones[j] = all_z[j];
            zoneMap[all_z[j]].push_back(i);
        }
    }
    cout << "Done." << endl;
    
    cout << "[Phase] Building Global Mesh Graph... ";
    for (int z = 0; z < NUM_ZONES; ++z) {
        auto& occupants = zoneMap[z];
        for (int node_id : occupants) {
            int z_idx = -1;
            for(int i=0; i<ZONES_PER_NODE; i++) {
                if ((*nodes)[node_id].zones[i] == z) { z_idx = i; break; }
            }
            if (z_idx == -1) continue;
            
            int attempts = 0;
            while ((*nodes)[node_id].mesh_counts[z_idx] < DEGREE && attempts < 20) {
                attempts++;
                int p = occupants[gen() % occupants.size()];
                if (p == node_id) continue;
                
                bool exists = false;
                for(int k=0; k<(*nodes)[node_id].mesh_counts[z_idx]; k++) {
                    if((*nodes)[node_id].mesh[z_idx][k] == p) exists = true;
                }
                if (exists) continue;

                (*nodes)[node_id].mesh[z_idx][(*nodes)[node_id].mesh_counts[z_idx]++] = p;
                
                int p_z_idx = -1;
                for(int i=0; i<ZONES_PER_NODE; i++) {
                    if ((*nodes)[p].zones[i] == z) { p_z_idx = i; break; }
                }
                if (p_z_idx != -1 && (*nodes)[p].mesh_counts[p_z_idx] < 10) {
                    bool p_exists = false;
                    for(int k=0; k<(*nodes)[p].mesh_counts[p_z_idx]; k++) {
                        if((*nodes)[p].mesh[p_z_idx][k] == node_id) p_exists = true;
                    }
                    if (!p_exists) {
                        (*nodes)[p].mesh[p_z_idx][(*nodes)[p].mesh_counts[p_z_idx]++] = node_id;
                    }
                }
            }
        }
    }
    
    auto t2 = chrono::steady_clock::now();
    cout << "Done. (" << chrono::duration_cast<chrono::milliseconds>(t2 - t1).count() << " ms)" << endl;
    
    auto runTest = [&](string name, int target_z, int start_time, int packet_id) {
        cout << "\n[Test] " << name << " (Zone " << target_z << ")" << endl;
        priority_queue<Event, vector<Event>, greater<Event>> pq;
        Metrics metrics;
        
        int author = -1;
        while(true) {
            author = gen() % NUM_NODES;
            if ((*nodes)[author].is_online) break;
        }
        
        pq.push({start_time, 0, author, target_z, packet_id, author});
        
        while(!pq.empty()) {
            Event ev = pq.top(); pq.pop();
            if (!(*nodes)[ev.node_id].is_online) continue;
            
            if (ev.type == 0) { // STEM
                if ((gen() % 100) < 10) { // Fluff
                    pq.push({ev.time, 1, ev.node_id, ev.zone_id, ev.packet_id, ev.author_id}); 
                } else { // Continue Stem
                    vector<int> available;
                    for(int z_idx=0; z_idx<ZONES_PER_NODE; z_idx++) {
                        for(int i=0; i<(*nodes)[ev.node_id].mesh_counts[z_idx]; i++) {
                            int n = (*nodes)[ev.node_id].mesh[z_idx][i];
                            if ((*nodes)[n].is_online) available.push_back(n);
                        }
                    }
                    if (available.empty()) {
                        pq.push({ev.time, 1, ev.node_id, ev.zone_id, ev.packet_id, ev.author_id}); 
                    } else {
                        int next_node = available[gen() % available.size()];
                        int delay = BASE_LATENCY_MS + (gen() % JITTER_MS);
                        pq.push({ev.time + delay, 0, next_node, ev.zone_id, ev.packet_id, ev.author_id});
                    }
                }
            } else if (ev.type == 1) { // FLUFF
                int start_node = ev.node_id;
                bool in_zone = false;
                for(int i=0; i<ZONES_PER_NODE; i++) {
                    if ((*nodes)[ev.node_id].zones[i] == ev.zone_id) in_zone = true;
                }
                if (!in_zone) {
                    const auto& mems = zoneMap[ev.zone_id];
                    for(int i=0; i<50; i++) {
                        int candidate = mems[gen() % mems.size()];
                        if ((*nodes)[candidate].is_online) {
                            start_node = candidate;
                            break;
                        }
                    }
                }
                pq.push({ev.time, 2, start_node, ev.zone_id, ev.packet_id, ev.author_id});
            } else if (ev.type == 2) { // GOSSIP
                if ((*nodes)[ev.node_id].seen_packet_id == ev.packet_id) continue;
                (*nodes)[ev.node_id].seen_packet_id = ev.packet_id;
                
                if (ev.node_id != ev.author_id) {
                    metrics.deliveries++;
                    metrics.max_latency = max(metrics.max_latency, ev.time - start_time);
                    metrics.sum_latency += (ev.time - start_time);
                }
                
                int z_idx = -1;
                for(int i=0; i<ZONES_PER_NODE; i++) {
                    if ((*nodes)[ev.node_id].zones[i] == ev.zone_id) { z_idx = i; break; }
                }
                if (z_idx != -1) {
                    vector<int> neighbors;
                    for(int i=0; i<(*nodes)[ev.node_id].mesh_counts[z_idx]; i++) {
                        int n = (*nodes)[ev.node_id].mesh[z_idx][i];
                        if ((*nodes)[n].is_online) neighbors.push_back(n);
                    }
                    shuffle(neighbors.begin(), neighbors.end(), gen);
                    int count = 0;
                    for(int n : neighbors) {
                        int delay = BASE_LATENCY_MS + (gen() % JITTER_MS);
                        pq.push({ev.time + delay, 2, n, ev.zone_id, ev.packet_id, ev.author_id});
                        metrics.total_gossip++;
                        if (++count >= FANOUT) break;
                    }
                }
            }
        }
        
        int expected = 0;
        for (int n : zoneMap[target_z]) {
            if ((*nodes)[n].is_online && n != author) expected++;
        }
        
        double rate = expected > 0 ? (double)metrics.deliveries / expected * 100.0 : 100.0;
        int avg_lat = metrics.deliveries > 0 ? (metrics.sum_latency / metrics.deliveries) : 0;
        
        // 帯域計算 (1秒間あたりの推定全ユーザー平均使用量)
        long long global_posts_per_sec = NUM_NODES / 200; // 例: 100万人なら秒間5000件
        if (global_posts_per_sec == 0) global_posts_per_sec = 1;
        
        double avg_msgs_per_post = (double)metrics.total_gossip / NUM_NODES;
        double avg_kbps = (avg_msgs_per_post * global_posts_per_sec * 500.0) / 1024.0;

        cout << "  * Expected Target Nodes: " << expected << endl;
        cout << "  * Delivered Copies: " << metrics.deliveries << " (" << rate << "%)" << endl;
        if (metrics.deliveries > 0) {
            cout << "  * Latency: Avg " << avg_lat << " ms, Max " << metrics.max_latency << " ms" << endl;
        } else {
            cout << "  * DHT MAILBOX Storage Only (No real-time delivery)" << endl;
        }
        cout << "  * Total Gossip Msgs: " << metrics.total_gossip << " (for 1 post)" << endl;
        cout << "  * Global Mails/Sec: " << global_posts_per_sec << " posts/sec" << endl;
        cout << "  * Avg Bandwidth/Node: " << avg_kbps << " KB/s  (推定・全ユーザー平均)" << endl;
    };
    
    runTest("Normal State Stability", 42, 0, 100);
    
    cout << "\n[Phase] Triggering " << CHURN_RATE*100 << "% Network Churn Attack..." << endl;
    int offline_count = 0;
    for(int i=0; i<NUM_NODES; i++) {
        if ((gen() % 100) < (CHURN_RATE * 100)) {
            (*nodes)[i].is_online = false;
            offline_count++;
        }
    }
    cout << "  " << offline_count << " nodes went instantly offline." << endl;
    
    runTest("Post-Churn Resilience", 42, 10000, 101);
    
    delete nodes;
    return 0;
}
