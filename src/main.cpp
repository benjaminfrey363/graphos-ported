#include <stdio.h>
#include <string.h>
#include <assert.h>

#include <unistd.h>
#include <pwd.h>
#include <array>
#include <iostream>
#include <cstring>
#include <fstream>
#include <stdexcept>

using namespace std;
#define MAX_PATH FILENAME_MAX

//#include "sgx_urts.h"
//#include "sgx_uae_service.h"
#include "../include/App.h"
#include "../include/OMAP/Types.h"
#include "../include/OMAP/GraphNode.h"
#include "../include/OMAP/Bid.h"
#include "../include/OMAP/Node.h"
#include "../include/OMAP/RAMStoreEnclaveInterface.h"

// Enclave header
#include "../Enclave/include/Enclave.h"

//#include "Enclave_u.h"
//#include "OMAP/RAMStoreEnclaveInterface.h"
/*
 * Copyright (C) 2011-2018 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

// This sample is confined to the communication between a SGX client platform
// and an ISV Application Server. 


#include <chrono>
#include <stdio.h>
#include <limits.h>
#include <unistd.h>
#include <map>
// Needed for definition of remote attestation messages.
//#include "remote_attestation_result.h"

//#include "Enclave_u.h"

// Needed to call untrusted key exchange library APIs, i.e. sgx_ra_proc_msg2.
//#include "sgx_ukey_exchange.h"

// Needed to get service provider's information, in your real project, you will
// need to talk to real server.
//#include "network_ra.h"

// Needed to create enclave and do ecall.
//#include "sgx_urts.h"

// Needed to query extended epid group id.
//#include "sgx_uae_service.h"

//#include "../service_provider/service_provider.h"

#ifndef SAFE_FREE
#define SAFE_FREE(ptr) {if (NULL != (ptr)) {free(ptr); (ptr) = NULL;}}
#endif





std::string exec(const char* cmd) {
    char buffer[128];
    std::string result = "";
    FILE* pipe = popen(cmd, "r");
    if (!pipe) throw std::runtime_error("popen() failed!");
    try {
        while (fgets(buffer, sizeof buffer, pipe) != NULL) {
            result += buffer;
        }
    } catch (...) {
        pclose(pipe);
        throw;
    }
    pclose(pipe);
    return result;
}



void initializeEdgeList(bytes<Key> secretkey, vector<GraphNode>* edgeList, char** edges) {
    unsigned long long blockSize = sizeof (GraphNode);
    unsigned long long clen_size = AES::GetCiphertextLength((int) (blockSize));
    unsigned long long plaintext_size = (blockSize);

    for (int i = 0; i < edgeList->size(); i++) {
        std::array<byte_t, sizeof (GraphNode) > data;

        const byte_t* begin = reinterpret_cast<const byte_t*> (std::addressof((*edgeList)[i]));
        const byte_t* end = begin + sizeof (GraphNode);
        std::copy(begin, end, std::begin(data));

        block buffer(data.begin(), data.end());
        block ciphertext = AES::Encrypt(secretkey, buffer, clen_size, plaintext_size);
        memcpy((uint8_t*) (*edges) + i * ciphertext.size(), ciphertext.data(), ciphertext.size());
    }
}

void initializeCiphertexts(bytes<Key> secretkey, map<Bid, string>* pairs, vector<block>* ciphertexts) {
    vector<Node*> nodes;
    for (auto pair : (*pairs)) {
        Node* node = new Node();
        node->key = pair.first;
        node->index = 0;
        std::fill(node->value.begin(), node->value.end(), 0);
        std::copy(pair.second.begin(), pair.second.end(), node->value.begin());
        node->leftID = 0;
        node->leftPos = -1;
        node->rightPos = -1;
        node->rightID = 0;
        node->pos = 0;
        node->isDummy = false;
        node->height = 1; // new node is initially added at leaf
        nodes.push_back(node);
    }

    unsigned long long blockSize = sizeof (Node);
    unsigned long long clen_size = AES::GetCiphertextLength((int) (blockSize));
    unsigned long long plaintext_size = (blockSize);

    for (int i = 0; i < nodes.size(); i++) {
        std::array<byte_t, sizeof (Node) > data;

        const byte_t* begin = reinterpret_cast<const byte_t*> (std::addressof((*nodes[i])));
        const byte_t* end = begin + sizeof (Node);
        std::copy(begin, end, std::begin(data));

        block buffer(data.begin(), data.end());
        block ciphertext = AES::Encrypt(secretkey, buffer, clen_size, plaintext_size);
        (*ciphertexts).push_back(ciphertext);
    }
}








/* Application entry */
//#define _T(x) x

int /*SGX_CDECL*/ main(int argc, char *argv[]) {
    (void) (argc);
    (void) (argv);


    AES::Setup();


    /* My Codes */
    int size = 0;
    string filename = "";
    string alg = "";
    if (argc > 1) {
        filename = string(argv[1]);
        alg = string(argv[2]);
    } else {
        filename = "datasets/V13E-256.in";
        alg = "OBLIVIOUS-BFS";
    }
    size = stoi(exec(string("wc -l " + filename + " | cut -d ' ' -f 1").c_str()));

    std::ifstream infile((filename).c_str());


    bytes<Key> secretkey{0};
    map<Bid, string> pairs;
    vector<block> ciphertexts;
    vector<GraphNode> edgeList;

    int node_numebr = 0;
    int testEdgesrc, testEdgeDst;

    for (int i = 0; i < size; i++) {
        int src, dst, weight;
        infile >> src >> dst >> weight;
        GraphNode node;
        node.src_id = src;
        node.dst_id = dst;
        node.weight = weight;
        if (src == dst) {
            node_numebr++;
        } else {
            if (node.weight == 0) {
                node.weight = 1;
            }
            edgeList.push_back(node);
        }
    }

    int encryptionSize = IV + AES::GetCiphertextLength(sizeof (GraphNode)); //SGX_AESGCM_IV_SIZE + SGX_AESGCM_MAC_SIZE = 28     sizeof(GraphNode)=64
    int maxPad = (int) pow(2, ceil(log2(edgeList.size())));
    char* edges = new char[maxPad * encryptionSize];
    long long maxSize = node_numebr;
    int depth = (int) (ceil(log2(maxSize)) - 1) + 1;
    int maxOfRandom = (long long) (pow(2, depth));
    unsigned long long bucketCount = maxOfRandom * 2 - 1;
    unsigned long long blockSize = sizeof (Node); // B  
    size_t blockCount = (size_t) (Z * bucketCount);
    unsigned long long storeBlockSize = (size_t) (IV + AES::GetCiphertextLength((int) (Z * (blockSize))));

    initializeEdgeList(secretkey, &edgeList, &edges);
    int edgeNumner = edgeList.size();
    edgeList.clear();

    for (int i = 1; i <= node_numebr; i++) {
        string omapKey = "?" + to_string(i);
        std::array< uint8_t, ID_SIZE > keyArray;
        keyArray.fill(0);
        std::copy(omapKey.begin(), omapKey.end(), std::begin(keyArray));
        std::array<byte_t, ID_SIZE> id;
        std::memcpy(id.data(), (const char*) keyArray.data(), ID_SIZE);
        Bid inputBid(id);
        pairs[inputBid] = "0-0";
    }

    initializeCiphertexts(secretkey, &pairs, &ciphertexts);

    setupMode = true;

    ocall_setup_ramStore(blockCount, storeBlockSize);
    ocall_nwrite_raw_ramStore(&ciphertexts);
    Utilities::startTimer(1);

    int op = -1;
    if (alg == "OBLIVIOUS-SSSP-OBLIVM") {
        op = 3;
    } else if (alg == "OBLIVIOUS-MST") {
        op = 2;
    } else if (alg == "OBLIVIOUS-BFS") {
        op = 1;
    }
    ecall_setup_with_small_memory(/*global_eid,*/ edgeNumner, node_numebr, (const char*) secretkey.data(), &edges, op);

   

    auto timer = Utilities::stopTimer(1);
    cout << "Setup Time:" << timer /*+ t*/ << " Microseconds" << endl;

    Utilities::startTimer(5);
    if (alg == "SEARCH-VERTEX" || alg == "search-vertex") {
        cout << "Running Search Vertex" << endl;
        ecall_search_node(string("1-1-0").c_str());
    } else if (alg == "DEL-VERTEX" || alg == "del-vertex") {
        cout << "Running Delete Vertex" << endl;
        ecall_del_node(string("1-1-0").c_str());
    } else if (alg == "DEL-EDGE" || alg == "del-edge") {
        cout << "Running Delete Edge" << endl;
        ecall_del_node(string(to_string(testEdgesrc) + "-" + to_string(testEdgeDst) + "-1").c_str());
    } else if (alg == "ADD-EDGE" || alg == "add-edge") {
        cout << "Running Add Edge" << endl;
        ecall_add_node(string("1-2-1").c_str(), &edges);
    } else if (alg == "PAGERANK" || alg == "pagerank") {
        cout << "Running PageRank" << endl;
        ecall_PageRank();
    } else if (alg == "BFS" || alg == "bfs") {
        cout << "Running BFS" << endl;
        ecall_BFS(1);
    } else if (alg == "OBLIVIOUS-BFS" || alg == "oblivious-bfs") {
        cout << "Running oblivious BFS" << endl;
        ecall_oblivious_BFS(1);
    } else if (alg == "NON-OBLIVIOUS-BFS" || alg == "non-oblivious-bfs") {
        cout << "Running non oblivious BFS" << endl;
        ecall_non_oblivious_BFS(1);
    } else if (alg == "DFS" || alg == "dfs") {
        cout << "Running DFS" << endl;
        ecall_DFS(1);
    } else if (alg == "MST" || alg == "mst") {
        cout << "Running MST" << endl;
        ecall_kruskal_minimum_spanning_tree(&edges);
    } else if (alg == "OBLIVIOUS-MST" || alg == "oblivious-mst") {
        cout << "Running Oblivious MST" << endl;
        ecall_oblivious_kruskal_minimum_spanning_tree(&edges);
    } else if (alg == "SSSP" || alg == "sssp") {
        cout << "Running SSSP" << endl;
        ecall_efficient_single_source_shortest_path(1);
    } else if (alg == "BFS-OBLIVM" || alg == "bfs-oblivm") {
        cout << "Running BFS-OBLIVM" << endl;
        int maxPad = (int) pow(2, ceil(log2(node_numebr * 2)));
        char* tovisit = new char[ 2 * maxPad * (28 + 8)]; //SGX_AESGCM_IV_SIZE + SGX_AESGCM_MAC_SIZE = 28     sizeof(pair<int,int>)=8
        char* adddata = new char[ 2 * maxPad * (28 + 8)];
        ecall_oblivm_BFS(1, &tovisit, &adddata);
        delete tovisit;
        delete adddata;
    } else if (alg == "DFS-OBLIVM" || alg == "dfs-oblivm") {
        cout << "Running DFS-OBLIVM" << endl;
        int maxPad = (int) pow(2, ceil(log2(node_numebr * 2)));
        unsigned long long pairBlockSize = sizeof (pair<int, int>);
        unsigned long long pairClenSize = AES::GetCiphertextLength((int) (pairBlockSize));
        unsigned long long pairStoreSingleBlockSize = pairClenSize + IV;
        char* tovisit = new char[ 2 * maxPad * pairStoreSingleBlockSize]; //SGX_AESGCM_IV_SIZE + SGX_AESGCM_MAC_SIZE = 28     sizeof(pair<int,int>)=8
        char* adddata = new char[ 2 * maxPad * pairStoreSingleBlockSize];
        ecall_oblivm_DFS(1, &tovisit, &adddata);
        delete tovisit;
        delete adddata;
    } else if (alg == "MST-OBLIVM" || alg == "mst-oblivm") {
        ecall_oblivm_kruskal_minimum_spanning_tree(&edges);
    } else if (alg == "SSSP-OBLIVM" || alg == "sssp-oblivm") {
        cout << "Running SSSP-OBLIVM" << endl;
        ecall_oblivm_single_source_shortest_path(1);
    } else if (alg == "OBLIVIOUS-SSSP-OBLIVM" || alg == "oblivious-sssp-oblivm") {
        cout << "Running Oblivious SSSP-OBLIVM" << endl;
        ecall_oblivious_oblivm_single_source_shortest_path(1);
    } else {
        cout << "unknown algorithm" << endl;
    }
    auto exectime = Utilities::stopTimer(5);
    cout << "Time:" << exectime << " Microseconds" << endl;



    /* Destroy the enclave */
    //------------------------------------------------------------------------------------------
    //------------------------------------------------------------------------------------------
    //------------------------------------------------------------------------------------------
    //------------------------------------------------------------------------------------------
    //------------------------------------------------------------------------------------------
    //sgx_destroy_enclave(global_eid);

    AES::Cleanup();

    return 0;
}

