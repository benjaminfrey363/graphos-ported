#include "include/Enclave.h"
#include "include/Types.hpp"
#include <assert.h>
//#include "Enclave_t.h"
//#include "sgx_tkey_exchange.h"
//#include "sgx_tcrypto.h"
#include "string.h"
#include <algorithm>
#include <math.h>
#include "include/OMAP.h"
#include "include/AES.hpp"
#include "include/GraphNode.h"
#include "include/ORAMEnclaveInterface.h"
#include "include/ORAM.hpp"

// interface outside of enclave
#include "../include/OMAP/RAMStoreEnclaveInterface.h"

#include <climits>

//int PLAINTEXT_LENGTH = sizeof (GraphNode);
//int PLAINTEXT_LENGTH2 = sizeof (pair<int, int>);
//int CIPHER_LENGTH = SGX_AESGCM_IV_SIZE + SGX_AESGCM_MAC_SIZE + PLAINTEXT_LENGTH;
//int CIPHER_LENGTH2 = SGX_AESGCM_IV_SIZE + SGX_AESGCM_MAC_SIZE + PLAINTEXT_LENGTH2;


#define MY_MAX 9999999
#define KV_MAX_SIZE 8192

void check_memory4(string text) {
    unsigned int required = 0x4f00000; // adapt to native uint
    char *mem = NULL;
    while (mem == NULL) {
        mem = (char*) malloc(required);
        if ((required -= 8) < 0xFFF) {
            if (mem) free(mem);
            printf("Cannot allocate enough memory\n");
            return;
        }
    }

    free(mem);
    mem = (char*) malloc(required);
    if (mem == NULL) {
        printf("Cannot enough allocate memory\n");
        return;
    }
    printf("%s = %d\n", text.c_str(), required);
    free(mem);
}

int vertexNumber = 0;
int edgeNumber = 0;
int maximumPad = 0;
map<Bid, string> finalPairs;
bytes<Key> tmpkey;
long long KV_index = 0;
unsigned long long edgeBlockSize = sizeof (GraphNode);
unsigned long long edgeClenSize = AES::GetCiphertextLength((int) (edgeBlockSize));
unsigned long long edgePlaintextSize = (edgeBlockSize);
unsigned long long edgeStoreSingleBlockSize = edgeClenSize + IV;
unsigned long long blockSize = sizeof (Node);
unsigned long long clen_size = AES::GetCiphertextLength((int) (blockSize));
unsigned long long plaintext_size = (blockSize);
unsigned long long storeSingleBlockSize = clen_size + IV;
unsigned long long pairBlockSize = sizeof (pair<int, int>);
unsigned long long pairClenSize = AES::GetCiphertextLength((int) (pairBlockSize));
unsigned long long pairPlaintextSize = (pairBlockSize);
unsigned long long pairStoreSingleBlockSize = pairClenSize + IV;

/*
void printf(const char *fmt, ...) {
    char buf[BUFSIZ] = {'\0'};
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    ocall_print_string(buf);
}
*/

string readOMAP(string omapKey) {
    std::array< uint8_t, ID_SIZE > keyArray;
    keyArray.fill(0);
    std::copy(omapKey.begin(), omapKey.end(), std::begin(keyArray));

    char* value = new char[16];
    ecall_read_node((const char*) keyArray.data(), value);
    string result(value);
    delete value;
    return result;
}

void writeOMAP(string omapKey, string omapValue) {
    std::array< uint8_t, ID_SIZE > keyArray;
    keyArray.fill(0);
    std::copy(omapKey.begin(), omapKey.end(), std::begin(keyArray));

    std::array< uint8_t, 16 > valueArray;
    valueArray.fill(0);
    std::copy(omapValue.begin(), omapValue.end(), std::begin(valueArray));

    ecall_write_node((const char*) keyArray.data(), (const char*) valueArray.data());
}

string readWriteOMAP(string omapKey, string omapValue) {
    std::array< uint8_t, ID_SIZE > keyArray;
    keyArray.fill(0);
    std::copy(omapKey.begin(), omapKey.end(), std::begin(keyArray));

    std::array< uint8_t, 16 > valueArray;
    valueArray.fill(0);
    std::copy(omapValue.begin(), omapValue.end(), std::begin(valueArray));
    char* oldvalue = new char[16];
    ecall_read_write_node((const char*) keyArray.data(), (const char*) valueArray.data(), oldvalue);
    string result(oldvalue);
    delete oldvalue;
    return result;
}

string readSetOMAP(string omapKey) {
    std::array< uint8_t, ID_SIZE > keyArray;
    keyArray.fill(0);
    std::copy(omapKey.begin(), omapKey.end(), std::begin(keyArray));

    char* value = new char[16];
    ecall_read_and_set_node((const char*) keyArray.data(), value);
    string result(value);
    delete value;
    return result;
}

vector<string> naiveSplitData(const string& str, const string& delim) {
    vector<string> tokens;
    size_t prev = 0, pos = 0;
    do {
        pos = str.find(delim, prev);
        if (pos == string::npos) pos = str.length();
        string token = str.substr(prev, pos - prev);
        if (!token.empty()) tokens.push_back(token);
        prev = pos + delim.length();
    } while (pos < str.length() && prev < str.length());
    return tokens;
}

vector<string> splitData(const string& str, const string& delim) {
    vector<string> tokens = {"", ""};
    int pos = 0;
    for (int i = 0; i < str.length(); i++) {
        bool cond = Node::CTeq(str.at(i), '-');
        pos = Node::conditional_select(i, pos, cond);
    }
    string token = str.substr(0, pos);
    tokens[0] = token;
    int begin = Node::conditional_select(pos, pos + 1, Node::CTeq(Node::CTcmp(pos + 1, str.length()), 1));
    token = str.substr(begin, str.length());
    tokens[1] = token;
    return tokens;

    //    vector<string> tokens;
    //    size_t prev = 0, pos = 0;
    //    do {
    //        pos = str.find(delim, prev);
    //        if (pos == string::npos) pos = str.length();
    //        string token = str.substr(prev, pos - prev);
    //        if (!token.empty()) tokens.push_back(token);
    //        prev = pos + delim.length();
    //    } while (pos < str.length() && prev < str.length());
    //    return tokens;
}

void addKeyValuePair(string key, string value, bytes<Key> secretKey) {
    if (key != "") {
        string omapKey = key;
        std::array< uint8_t, ID_SIZE > keyArray;
        keyArray.fill(0);
        std::copy(omapKey.begin(), omapKey.end(), std::begin(keyArray));
        std::array<byte_t, ID_SIZE> id;
        std::memcpy(id.data(), (const char*) keyArray.data(), ID_SIZE);
        Bid inputBid(id);
        finalPairs[inputBid] = value;
    }
    if (finalPairs.size() == KV_MAX_SIZE || ((key == "") && (value == ""))) {
        char* tmp = new char[finalPairs.size() * storeSingleBlockSize];
        vector<long long> indexes;
        long long j = 0;
        for (auto pair : finalPairs) {
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


            indexes.push_back(KV_index);
            KV_index++;

            std::array<byte_t, sizeof (Node) > data;

            const byte_t* begin = reinterpret_cast<const byte_t*> (std::addressof(((*node))));
            const byte_t* end = begin + sizeof (Node);
            std::copy(begin, end, std::begin(data));

            block buffer(data.begin(), data.end());
            block ciphertext = AES::Encrypt(secretKey, buffer, clen_size, plaintext_size);
            std::memcpy(tmp + j * ciphertext.size(), ciphertext.data(), storeSingleBlockSize);
            delete node;
            j++;
        }
        ocall_nwrite_rawRamStore_for_graph(finalPairs.size(), indexes.data(), (const char*) tmp, storeSingleBlockSize * finalPairs.size());
        delete tmp;
        finalPairs.clear();
    }

}



// forward definition
void ecall_pad_nodes(char** edgeList) {
    int maxPad = (int) pow(2, ceil(log2(edgeNumber)));

    for (int i = edgeNumber; i < maxPad; i++) {
        GraphNode* node = new GraphNode();
        node->src_id = -1;
        node->dst_id = -1;
        node->weight = MY_MAX;


        block b = GraphNode::convertNodeToBlock(node);
        block ciphertext = AES::Encrypt(tmpkey, b, edgeClenSize, edgeBlockSize);
        memcpy((uint8_t*) (*edgeList) + i * ciphertext.size(), ciphertext.data(), ciphertext.size());
        delete node;

    }
}





void ecall_setup_with_small_memory(int eSize, long long vSize, const char* secretKey, char** edgeList, int op = -1) {
    
    map<int, int> outgoing_counts;
    map<int, int> incoming_counts;
    
    std::memcpy(tmpkey.data(), secretKey, Key);
    size_t depth = (int) (ceil(log2(vSize)) - 1) + 1;
    long long maxOfRandom = (long long) (pow(2, depth));
    vertexNumber = vSize;
    edgeNumber = eSize;
    maximumPad = (int) pow(2, ceil(log2(edgeNumber)));
    long long KVNumber = 0;

    OMAP* omap = new OMAP(maxOfRandom, vSize, tmpkey);

    unsigned long long maxSize = (vertexNumber + edgeNumber)*4;
    depth = (int) (ceil(log2(maxSize)) - 1) + 1;
    maxOfRandom = (long long) (pow(2, depth));
    unsigned long long bucketCount = maxOfRandom * 2 - 1;
    unsigned long long blockSize = sizeof (Node); // B  
    unsigned long long blockCount = (size_t) (Z * bucketCount);
    ocall_finish_setup();
    ocall_setup_ramStore(blockCount, blockSize);
    ocall_begin_setup();


    for (int i = 0; i < eSize; i++) {
        if (i % 100 == 0) {
            printf("%d/%d of edges processed\n", i, eSize);
        }
        block ciphertext((*edgeList) + i*edgeStoreSingleBlockSize, (*edgeList)+ (i + 1) * edgeStoreSingleBlockSize);
        block buffer = AES::Decrypt(tmpkey, ciphertext, edgeClenSize);
        GraphNode* curEdge = GraphNode::convertBlockToNode(buffer);

        /*
        string srcBid = "?" + to_string(curEdge->src_id);
        std::array<byte_t, ID_SIZE> srcid;
        std::memcpy(srcid.data(), srcBid.data(), ID_SIZE);
        Bid srcInputBid(srcid);
        string srcCntStr = omap->incPart(srcInputBid, true);

        vector<string> parts = splitData(srcCntStr, "-");
        int outSrc = stoi(parts[0]) + 1;
        int inSrc = stoi(parts[1]);

        string dstBid = "?" + to_string(curEdge->dst_id);
        std::array<byte_t, ID_SIZE> dstid;
        std::memcpy(dstid.data(), dstBid.data(), ID_SIZE);
        Bid dstInputBid(dstid);
        string dstCntStr = omap->incPart(dstInputBid, false);

        parts = splitData(dstCntStr, "-");
        int outDst = stoi(parts[0]);
        int inDst = stoi(parts[1]) + 1;
        */

        // replaced - increment and get the current counts from our local maps
        outgoing_counts[curEdge->src_id]++;
        incoming_counts[curEdge->dst_id]++;
        int outSrc = outgoing_counts[curEdge->src_id];
        int inDst = incoming_counts[curEdge->dst_id];

        string src = to_string(curEdge->src_id);
        string dst = to_string(curEdge->dst_id);
        string weight = to_string(curEdge->weight);

        printf("Writing to OMAP -> Key: [$%s-%s] Value: [%s-%s]\n", src.c_str(), to_string(outSrc).c_str(), dst.c_str(), weight.c_str());
        addKeyValuePair("$" + src + "-" + to_string(outSrc), dst + "-" + weight, tmpkey);
        
        printf("Writing to OMAP -> Key: [*%s-%s] Value: [%s-%s]\n", dst.c_str(), to_string(inDst).c_str(), src.c_str(), weight.c_str());
        addKeyValuePair("*" + dst + "-" + to_string(inDst), src + "-" + weight, tmpkey);
        
        printf("Writing to OMAP -> Key: [!%s-%s] Value: [%s-%s-%s]\n", src.c_str(), dst.c_str(), weight.c_str(), to_string(outSrc).c_str(), to_string(inDst).c_str());
        addKeyValuePair("!" + src + "-" + dst, weight + "-" + to_string(outSrc) + "-" + to_string(inDst), tmpkey);
        
        KVNumber += 3;

        //SSSP SETUP
        if (op == 3) {
            addKeyValuePair("&" + to_string(i), "0-0", tmpkey);
            KVNumber++;
        }

        delete curEdge;
    }

    for (int i = 1; i <= vSize; i++) {
        if (i % 100 == 0) {
            printf("%d/%d of vertices processed\n", i, vSize);
        }
        string bid = "?" + to_string(i);
        std::array<byte_t, ID_SIZE> id;
        std::memcpy(id.data(), bid.data(), ID_SIZE);
        Bid inputBid(id);
        string value = omap->find(inputBid);
        addKeyValuePair(bid, value, tmpkey);
        KVNumber++;

        //SSSP SETUP
        if (op == 1) {
            bid = "@" + to_string(i);
            value = "";
            addKeyValuePair(bid, value, tmpkey);
            KVNumber++;
            bid = "%" + to_string(i);
            value = "";
            addKeyValuePair(bid, value, tmpkey);
            KVNumber++;
        } else if (op == 2) {
            bid = "/" + to_string(i);
            value = to_string(i);
            addKeyValuePair(bid, value, tmpkey);
            KVNumber++;
        } else if (op == 3) {
            bid = "/" + to_string(i);
            value = to_string(MY_MAX);
            addKeyValuePair(bid, value, tmpkey);
            KVNumber++;
        }
    }

    if (op == 1) {
        string bid = "@" + to_string(0);
        string value = "";
        addKeyValuePair(bid, value, tmpkey);
        KVNumber++;
        bid = "%" + to_string(0);
        value = "";
        addKeyValuePair(bid, value, tmpkey);
        KVNumber++;
    } else if (op == 2 || op == 3) {
        string bid = "/" + to_string(0);
        string value = to_string(0);
        addKeyValuePair(bid, value, tmpkey);
        KVNumber++;
    }

    // added separate writing loop
    for (int i = 1; i <= vSize; i++) {
        string bid = "?" + to_string(i);
        string value = to_string(outgoing_counts[i]) + "-" + to_string(incoming_counts[i]);
        addKeyValuePair(bid, value, tmpkey);
        KVNumber++;
    }


    addKeyValuePair("", "", tmpkey);
    ecall_pad_nodes(edgeList);

    ocall_finish_setup();
    ecall_setup_omap_with_small_memory((vertexNumber + edgeNumber)*4, KVNumber, secretKey);

}

/**
 *  (#-cnt) -> V1,V2,...,Vn
 *  ($-src-cnt) -> dst
 *  (?-id) -> (Number of outgoing edges,Number of incoming edges)
 *  (*-dst-cnt) -> src
 *  (!-src-dst) -> (weight,src_cnt,dst_cnt)
 * @param data
 */
void ecall_del_node(const char* data) {
    string inputData(data);
    vector<string> nodesInfo = naiveSplitData(inputData, "-");
    if (nodesInfo[0] == nodesInfo[1]) {
        string vertex = nodesInfo[0];
        string res = readOMAP("?" + vertex);
        vector<string> parts = splitData(res, "-");
        int in_u = stoi(parts[0]);
        int out_u = stoi(parts[1]);
        writeOMAP("?" + vertex, "");

        for (int i = 1; i <= in_u; i++) {
            string src = vertex;
            res = readOMAP("$" + src + "-" + to_string(i));
            string dst = splitData(res, "-")[0];

            res = readOMAP("!" + src + "-" + dst);
            parts = splitData(res, "-");
            string cnt_dst = parts[2];
            writeOMAP("!" + src + "-" + dst, "");

            res = readOMAP("?" + dst);
            parts = splitData(res, "-");
            string in_dst = parts[0];
            string out_dst = parts[1];

            writeOMAP("*" + dst + "-" + cnt_dst, readOMAP("*" + dst + "-" + out_dst));

            in_dst = to_string(stoi(in_dst) - 1);
            writeOMAP("?" + dst, in_dst + "-" + out_dst);
        }

        for (int i = 1; i <= out_u; i++) {
            string dst = vertex;
            res = readOMAP("*" + dst + "-" + to_string(i));
            string src = splitData(res, "-")[0];


            res = readOMAP("!" + src + "-" + dst);
            parts = splitData(res, "-");
            string cnt_src = parts[1];
            writeOMAP("!" + src + "-" + dst, "");

            res = readOMAP("?" + src);
            parts = splitData(res, "-");
            string in_src = parts[0];
            string out_src = parts[1];

            writeOMAP("$" + src + "-" + cnt_src, readOMAP("$" + src + "-" + out_src));

            out_src = to_string(stoi(out_src) - 1);
            writeOMAP("?" + src, in_src + "-" + out_src);
        }


    } else {
        string src = nodesInfo[0];
        string dst = nodesInfo[1];

        string res = readOMAP("!" + src + "-" + dst);
        vector<string> parts = splitData(res, "-");
        string cnt_src = parts[1];
        string cnt_dst = parts[2];
        writeOMAP("!" + src + "-" + dst, "");

        res = readOMAP("?" + src);
        parts = splitData(res, "-");
        string in_src = parts[1];
        string out_src = parts[0];

        res = readOMAP("?" + dst);
        parts = splitData(res, "-");
        string in_dst = parts[1];
        string out_dst = parts[0];

        string tmp1 = readOMAP("$" + src + "-" + out_src);
        string tmp2 = readOMAP("*" + dst + "-" + out_dst);
        writeOMAP("$" + src + "-" + cnt_src, tmp1);
        writeOMAP("*" + dst + "-" + cnt_dst, tmp2);

        out_src = to_string(stoi(out_src) - 1);
        in_dst = to_string(stoi(in_dst) - 1);

        writeOMAP("?" + src, out_src + "-" + in_src);
        writeOMAP("?" + dst, out_dst + "-" + in_dst);

    }
}

void ecall_search_node(const char* data) {
    string inputData(data);
    vector<string> nodesInfo = naiveSplitData(inputData, "-");
    if (nodesInfo[0] == nodesInfo[1]) {
        string vertex = nodesInfo[0];
        string res = readOMAP("?" + vertex);
    } else {
        string src = nodesInfo[0];
        string dst = nodesInfo[1];

        string res = readOMAP("!" + src + "-" + dst);
    }
}



/**
 *  (#-cnt) -> V1,V2,...,Vn
 *  ($-src-cnt) -> (dst,weight)
 *  (?-id) -> (Number of outgoing edges,Number of incoming edges)
 *  (*-dst-cnt) -> (src,weight)
 *  (!-src-dst) -> (weight,src_cnt,dst_cnt)
 * @param data
 */
void ecall_add_node(const char* data, char** edgeList) {
    string inputData(data);
    vector<string> nodesInfo = naiveSplitData(inputData, "-");
    if (nodesInfo[0] == nodesInfo[1]) {
        vertexNumber++;
    } else {
        string src = nodesInfo[0];
        string dst = nodesInfo[1];
        string weight = nodesInfo[2];

        GraphNode* node = new GraphNode();
        node->src_id = stoi(src);
        node->dst_id = stoi(dst);
        node->weight = stoi(weight);

        block b = GraphNode::convertNodeToBlock(node);
        block ciphertext = AES::Encrypt(tmpkey, b, edgeClenSize, edgeBlockSize);
        memcpy((uint8_t*) (*edgeList) + edgeNumber * ciphertext.size(), ciphertext.data(), ciphertext.size());

        string srcVertex = readOMAP("?" + src);
        int srcOutGoingEdges = 1;
        int srcIncomingEdges = 0;
        if (srcVertex != "") {
            vector<string> parts = splitData(srcVertex, "-");
            srcOutGoingEdges = stoi(parts[0]) + 1;
            srcIncomingEdges = stoi(parts[1]);
        }
        writeOMAP("?" + src, to_string(srcOutGoingEdges) + "-" + to_string(srcIncomingEdges));
        writeOMAP("$" + src + "-" + to_string(srcOutGoingEdges), dst + "-" + weight);

        string dstVertex = readOMAP("?" + dst);
        int dstOutGoingEdges = 0;
        int dstIncomingEdges = 1;

        if (dstVertex != "") {
            vector<string> parts = splitData(dstVertex, "-");
            dstOutGoingEdges = stoi(parts[0]);
            dstIncomingEdges = stoi(parts[1]) + 1;
        }
        writeOMAP("?" + dst, to_string(dstOutGoingEdges) + "-" + to_string(dstIncomingEdges));
        writeOMAP("*" + dst + "-" + to_string(dstIncomingEdges), src + "-" + weight);
        edgeNumber++;

        writeOMAP("!" + src + "-" + dst, weight + "-" + to_string(srcOutGoingEdges) + "-" + to_string(dstIncomingEdges));

        delete node;
    }
}

void ecall_PageRank() {
    int vertexCounter = 1;
    string vertex = "";
    do {
        string omapKey = "#" + to_string(vertexCounter);
        vertex = readOMAP(omapKey);
        if (vertex != "") {
            double weightedRank = 0;
            int cnt = 1;
            omapKey = "*" + vertex + "-" + to_string(cnt);
            string currentEdge = readOMAP(omapKey);
            while (currentEdge != "") {
                weightedRank += 1;
                cnt++;
                omapKey = "*" + vertex + "-" + to_string(cnt);
                currentEdge = readOMAP(omapKey);
            }
            weightedRank = weightedRank * 0.85 + 0.15;
            //printf("Vertex:%s Rank:%f\n",vertex,weightedRank);
            //writeOMAP(string("@" + vertex), to_string(weightedRank));
        }
        vertexCounter++;
    } while (vertex != "");
}

void ecall_BFS(int src) {
    int Qcnt = 1;
    int curQCnt = 1;
    string source = to_string(src);
    writeOMAP(string("@" + to_string(Qcnt)), source);
    writeOMAP(string("%") + source, to_string(Qcnt));
    Qcnt++;
    while (curQCnt != Qcnt) {
        source = readOMAP(string("@" + to_string(curQCnt)));
        curQCnt++;
        printf("Node:%s Visisted\n", source.c_str());
        int cnt = 1;
        string omapKey = "$" + source + "-" + to_string(cnt);
        string dstStr = readOMAP(omapKey);
        while (dstStr != "") {
            vector<string> parts = splitData(dstStr, "-");
            string dst = parts[0];
            string visited = readOMAP(string("%") + dst);
            if (visited == "") {
                writeOMAP(string("@" + to_string(Qcnt)), dst);
                writeOMAP(string("%") + dst, to_string(Qcnt));
                Qcnt++;
            } else {
                writeOMAP("&0", "");
                writeOMAP("&0", "");
                Qcnt = Qcnt;
            }
            cnt++;
            omapKey = "$" + source + "-" + to_string(cnt);
            dstStr = readOMAP(omapKey);
        }
    }
}

void ecall_non_oblivious_BFS(int src) {
    int cost[31][31], j, k = 1, n = 31, qu[31], front, rare, v = src, visit[31], visited[31];

    cost[1][2] = 1;
    cost[2][3] = 1;
    cost[3][4] = 1;
    cost[4][5] = 1;
    cost[5][6] = 1;
    cost[6][7] = 1;
    cost[7][8] = 1;
    cost[8][9] = 1;
    cost[9][10] = 1;
    cost[10][11] = 1;
    cost[11][12] = 1;
    cost[12][13] = 1;
    cost[13][14] = 1;
    cost[14][15] = 1;
    cost[15][16] = 1;
    cost[16][17] = 1;
    cost[17][18] = 1;
    cost[18][19] = 1;
    cost[19][20] = 1;
    cost[20][21] = 1;
    cost[21][22] = 1;
    cost[22][23] = 1;
    cost[23][24] = 1;
    cost[24][25] = 1;
    cost[25][26] = 1;
    cost[26][27] = 1;
    cost[27][28] = 1;
    cost[28][29] = 1;
    cost[29][30] = 1;
    cost[30][31] = 1;
    cost[31][32] = 1;
    cost[32][33] = 1;
    cost[33][34] = 1;
    cost[14][9] = 1;
    cost[5][9] = 1;
    cost[17][3] = 1;
    cost[13][3] = 1;
    cost[29][27] = 1;
    cost[27][16] = 1;
    cost[4][31] = 1;
    cost[15][27] = 1;
    cost[10][27] = 1;
    cost[29][14] = 1;
    cost[8][2] = 1;
    cost[24][6] = 1;
    cost[29][8] = 1;
    cost[31][17] = 1;
    cost[17][10] = 1;
    cost[23][6] = 1;
    cost[16][24] = 1;
    cost[29][18] = 1;
    cost[5][19] = 1;
    cost[32][24] = 1;
    cost[26][20] = 1;
    cost[6][34] = 1;
    cost[12][25] = 1;
    cost[6][31] = 1;
    cost[11][22] = 1;
    cost[26][31] = 1;
    cost[1][13] = 1;
    cost[23][11] = 1;
    cost[25][18] = 1;
    cost[27][6] = 1;
    cost[13][1] = 1;
    cost[18][26] = 1;
    cost[30][23] = 1;
    cost[17][2] = 1;
    cost[16][27] = 1;
    cost[20][26] = 1;
    cost[1][14] = 1;
    cost[34][22] = 1;
    cost[24][9] = 1;
    cost[5][22] = 1;
    cost[24][7] = 1;
    cost[6][22] = 1;
    cost[1][32] = 1;
    cost[30][24] = 1;
    cost[6][2] = 1;
    cost[21][12] = 1;
    cost[16][33] = 1;
    cost[16][18] = 1;
    cost[17][12] = 1;
    cost[7][32] = 1;
    cost[31][28] = 1;
    cost[3][24] = 1;
    cost[11][13] = 1;
    cost[1][11] = 1;
    cost[3][14] = 1;
    cost[11][1] = 1;
    cost[18][22] = 1;
    cost[30][14] = 1;
    cost[2][28] = 1;
    cost[26][29] = 1;
    cost[6][11] = 1;
    cost[28][24] = 1;
    cost[17][30] = 1;
    cost[20][4] = 1;
    cost[1][17] = 1;
    cost[17][14] = 1;
    cost[9][5] = 1;
    cost[8][33] = 1;
    cost[29][15] = 1;
    cost[23][21] = 1;
    cost[30][9] = 1;
    cost[13][26] = 1;
    cost[25][14] = 1;
    cost[6][9] = 1;
    cost[15][31] = 1;
    cost[13][17] = 1;
    cost[21][3] = 1;
    cost[6][14] = 1;
    cost[26][13] = 1;
    cost[31][16] = 1;
    cost[5][17] = 1;
    cost[1][31] = 1;
    cost[16][5] = 1;
    cost[5][14] = 1;
    cost[21][26] = 1;
    cost[11][29] = 1;
    cost[24][31] = 1;
    cost[11][17] = 1;
    cost[4][29] = 1;
    cost[14][25] = 1;
    cost[34][21] = 1;
    cost[11][32] = 1;
    cost[3][13] = 1;
    cost[33][28] = 1;
    cost[7][29] = 1;
    cost[5][26] = 1;
    cost[31][27] = 1;
    cost[3][2] = 1;
    cost[12][9] = 1;
    cost[5][7] = 1;
    cost[4][28] = 1;
    cost[31][12] = 1;
    cost[11][34] = 1;
    cost[21][34] = 1;
    cost[13][22] = 1;
    cost[32][7] = 1;
    cost[32][14] = 1;
    cost[34][24] = 1;
    cost[29][33] = 1;
    cost[9][32] = 1;
    cost[16][23] = 1;
    cost[9][22] = 1;
    cost[2][9] = 1;
    cost[10][32] = 1;
    cost[19][33] = 1;
    cost[21][23] = 1;
    cost[32][8] = 1;
    cost[6][18] = 1;
    cost[19][14] = 1;
    cost[29][11] = 1;
    cost[17][25] = 1;
    cost[33][32] = 1;
    cost[29][13] = 1;
    cost[4][30] = 1;
    cost[16][7] = 1;
    cost[28][10] = 1;
    cost[30][25] = 1;
    cost[25][8] = 1;
    cost[28][2] = 1;
    cost[14][6] = 1;
    cost[26][14] = 1;
    cost[33][7] = 1;
    cost[12][4] = 1;
    cost[23][13] = 1;
    cost[33][22] = 1;
    cost[3][7] = 1;
    cost[10][29] = 1;
    cost[30][18] = 1;
    cost[29][25] = 1;
    cost[23][9] = 1;
    cost[28][26] = 1;
    cost[30][12] = 1;
    cost[2][17] = 1;
    cost[33][26] = 1;
    cost[12][21] = 1;
    cost[11][20] = 1;
    cost[28][34] = 1;
    cost[5][8] = 1;
    cost[5][25] = 1;
    cost[9][23] = 1;
    cost[30][16] = 1;
    cost[13][27] = 1;
    cost[9][18] = 1;
    cost[12][3] = 1;
    cost[33][1] = 1;
    cost[32][17] = 1;
    cost[13][32] = 1;
    cost[18][6] = 1;
    cost[28][16] = 1;
    cost[1][8] = 1;
    cost[28][13] = 1;
    cost[23][27] = 1;
    cost[8][15] = 1;
    cost[1][15] = 1;
    cost[1][25] = 1;
    cost[18][5] = 1;
    cost[18][21] = 1;
    cost[31][22] = 1;
    cost[30][17] = 1;
    cost[13][7] = 1;
    cost[30][32] = 1;
    cost[9][26] = 1;
    cost[31][18] = 1;
    cost[21][28] = 1;
    cost[3][34] = 1;
    cost[23][10] = 1;
    cost[18][32] = 1;
    cost[27][34] = 1;
    cost[4][13] = 1;
    cost[26][11] = 1;
    cost[15][4] = 1;
    cost[28][3] = 1;
    cost[16][25] = 1;
    cost[16][19] = 1;
    cost[21][4] = 1;
    cost[16][26] = 1;
    cost[13][16] = 1;
    cost[30][27] = 1;
    cost[23][1] = 1;
    ocall_start_timer(45);
    visited[v] = 1;
    k = 1;
    while (k < n) {
        for (j = 1; j < n; j++) {
            if (cost[v][j] != 0 && visited[j] != 1 && visit[j] != 1) {
                visit[j] = 1;
                qu[rare++] = j;
            }
        }
        v = qu[front++];
        k++;
        visit[v] = 0;
        visited[v] = 1;
    }
    double gg;
    gg = ocall_stop_timer(45);
    printf("time %f\n", gg);

}

string CTString(string a, string b, int choice) {
    unsigned int one = 1;
    string result = "";
    int maxSize = max(a.length(), b.length());
    for (int i = 0; i < maxSize; i++) {
        a += " ";
        b += " ";
    }
    for (int i = 0; i < maxSize; i++) {
        result += (~((unsigned int) choice - one) & a.at(i)) | ((unsigned int) (choice - one) & b.at(i));
    }
    result.erase(std::find_if(result.rbegin(), result.rend(), std::not1(std::ptr_fun<int, int>(std::isspace))).base(), result.end());
    return result;
}

bool CTeq(string a, string b) {
    a.erase(std::find_if(a.rbegin(), a.rend(), std::not1(std::ptr_fun<int, int>(std::isspace))).base(), a.end());
    b.erase(std::find_if(b.rbegin(), b.rend(), std::not1(std::ptr_fun<int, int>(std::isspace))).base(), b.end());
    bool res = Node::CTeq((int) a.length(), (int) b.length());
    for (int i = 0; i < min((int) a.length(), (int) b.length()); i++) {
        res = Node::conditional_select(false, res, !Node::CTeq(a.at(i), b.at(i)));
    }
    return res;
}

void ecall_oblivious_BFS(int src) {
    int Qcnt = 1;
    int curQCnt = 1, cnt;
    string source = to_string(src), visited = "";
    readWriteOMAP(string("@" + to_string(Qcnt)), source);
    readWriteOMAP(string("%") + source, to_string(Qcnt));
    Qcnt++;
    bool outerL = true, mostIner = false;
    while (curQCnt != Qcnt) {
        string tmp = readOMAP(string("@" + to_string(curQCnt)));
        source = CTString(tmp, source, outerL);
        //        source = outerL ? tmp : source;
        curQCnt = Node::conditional_select(curQCnt + 1, curQCnt, outerL); //
        //        curQCnt = outerL ? curQCnt + 1 : curQCnt;
        if (outerL) {
            printf("Node:%s Visisted\n", source.c_str());
        }
        cnt = Node::conditional_select(1, cnt, outerL);
        //        cnt = outerL ? 1 : cnt;
        string trm = readOMAP(string("$" + source + "-" + to_string(cnt)));
        outerL = Node::conditional_select(true, false, Node::CTeq(trm.length(), 0));
        //        outerL = (trm == "" ? true : false);
        vector<string> parts = splitData(trm, "-");
        parts.push_back("");
        string dst = parts[0];
        //        string dst = parts.size() > 0 ? parts[0] : "";
        tmp = readOMAP(string("%") + dst);
        visited = CTString(visited, tmp, outerL);
        //        visited = outerL ? visited : tmp;
        mostIner = (Node::CTeq(visited.length(), 0) && outerL == false);
        //        mostIner = (visited == "" && outerL == false);
        string mapKey = CTString("@" + to_string(Qcnt), "&0", mostIner);
        //        string mapKey = mostIner ? ("@" + to_string(Qcnt)) : "&0";
        readWriteOMAP(mapKey, dst);
        mapKey = CTString((string("%") + dst), "&0", mostIner);
        //        mapKey = mostIner ? (string("%") + dst) : "&0";
        readWriteOMAP(mapKey, to_string(Qcnt));
        Qcnt = Node::conditional_select(Qcnt + 1, Qcnt, mostIner);
        //        Qcnt = mostIner ? Qcnt + 1 : Qcnt;
        cnt = Node::conditional_select(cnt, cnt + 1, outerL);
        //        cnt = outerL ? cnt : cnt + 1;
    }
}

void ecall_DFS(int src) {
    int Qcnt = 1;
    string source = to_string(src);
    writeOMAP(string("@" + to_string(Qcnt)), source);
    writeOMAP(string("%") + source, to_string(Qcnt));
    while (0 != Qcnt) {
        source = readOMAP(string("@" + to_string(Qcnt)));
        Qcnt--;
        printf("Node:%s Visisted\n", source.c_str());
        int cnt = 1;
        string omapKey = "$" + source + "-" + to_string(cnt);
        string dstStr = readOMAP(omapKey);
        while (dstStr != "") {
            vector<string> parts = splitData(dstStr, "-");
            string dst = parts[0];
            string visited = readOMAP(string("%") + dst);
            if (visited == "") {
                Qcnt++;
                writeOMAP(string("@" + to_string(Qcnt)), dst);
                writeOMAP(string("%") + dst, to_string(Qcnt));
            } else {
                Qcnt = Qcnt;
                writeOMAP("&0", "");
                writeOMAP("&0", "");
            }
            cnt++;
            omapKey = "$" + source + "-" + to_string(cnt);
            dstStr = readOMAP(omapKey);
        }
    }
}

pair<int, int> getToVisit(char** tovisit, int index) {
    block ciphertext((*tovisit) + index*pairStoreSingleBlockSize, (*tovisit)+ (index + 1) * pairStoreSingleBlockSize);
    block c1 = AES::Decrypt(tmpkey, ciphertext, pairClenSize);
    pair<int, int> pairValue;
    std::array<byte_t, sizeof (pair<int, int>) > arr;
    std::copy(c1.begin(), c1.begin() + sizeof (pair<int, int>), arr.begin());
    from_bytes(arr, pairValue);
    return pairValue;
}

void setToVisit(char** tovisit, int index, pair<int, int> data) {
    std::array<byte_t, sizeof (pair<int, int>) > data1 = to_bytes(data);
    block b1(data1.begin(), data1.end());
    block ciphertext = AES::Encrypt(tmpkey, b1, pairClenSize, pairPlaintextSize);
    memcpy((uint8_t*) (*tovisit) + index * pairStoreSingleBlockSize, ciphertext.data(), pairStoreSingleBlockSize);
}

void setAdd(char** add, int index, pair<int, int> data) {
    std::array<byte_t, sizeof (pair<int, int>) > data1 = to_bytes(data);
    block b1(data1.begin(), data1.end());
    block ciphertext = AES::Encrypt(tmpkey, b1, pairClenSize, pairPlaintextSize);
    memcpy((uint8_t*) (*add) + index * pairStoreSingleBlockSize, ciphertext.data(), pairStoreSingleBlockSize);
}

void mergeAddAndTovisit(char** add, char** tovisit) {
    memcpy((*tovisit) + pairStoreSingleBlockSize*vertexNumber, (*add), vertexNumber * pairStoreSingleBlockSize);
}

void compAndSwap2(char** tovisit, int i, int j, bool dir, int step, bool BFS) {
    pair<int, int> lhs = getToVisit(tovisit, i);
    pair<int, int> rhs = getToVisit(tovisit, j);

    bool cond1 = Node::CTeq(step, 1);

    bool cond1_1 = Node::CTeq(dir, Node::CTeq(Node::CTcmp(lhs.first, rhs.first), 1) || (!BFS && Node::CTeq(lhs.first, rhs.first) && Node::CTeq(Node::CTcmp(rhs.second, lhs.second), 1))
            || (BFS && Node::CTeq(lhs.first, rhs.first) && Node::CTeq(Node::CTcmp(rhs.second, lhs.second), -1)));
    //    bool cond1_1 = dir == ((lhs.first > rhs.first) || (BFS == false && lhs.first == rhs.first && rhs.second > lhs.second)
    //            || (BFS == true && lhs.first == rhs.first && rhs.second < lhs.second));

    bool cond2_1 = Node::CTeq(dir, (!BFS && !Node::CTeq(lhs.first, MY_MAX) && !Node::CTeq(rhs.first, MY_MAX) && !Node::CTeq(lhs.second, MY_MAX) && !Node::CTeq(rhs.second, MY_MAX) && Node::CTeq(Node::CTcmp(lhs.second, rhs.second), -1)) ||
            (BFS && !Node::CTeq(lhs.first, MY_MAX) && !Node::CTeq(rhs.first, MY_MAX) && !Node::CTeq(lhs.second, MY_MAX) && !Node::CTeq(rhs.second, MY_MAX) && Node::CTeq(Node::CTcmp(lhs.second, rhs.second), 1)) ||
            (!Node::CTeq(lhs.first, MY_MAX) && !Node::CTeq(rhs.first, MY_MAX) && Node::CTeq(lhs.second, MY_MAX) && !Node::CTeq(rhs.second, MY_MAX)) ||
            (Node::CTeq(lhs.first, MY_MAX) && !Node::CTeq(rhs.first, MY_MAX))
            );
    //    bool cond2_1 = dir == ((BFS == false && lhs.first != MY_MAX && rhs.first != MY_MAX && lhs.second != MY_MAX && rhs.second != MY_MAX && lhs.second < rhs.second) ||
    //            (BFS == true && lhs.first != MY_MAX && rhs.first != MY_MAX && lhs.second != MY_MAX && rhs.second != MY_MAX && lhs.second > rhs.second) ||
    //            (lhs.first != MY_MAX && rhs.first != MY_MAX && lhs.second == MY_MAX && rhs.second != MY_MAX) ||
    //            (lhs.first == MY_MAX && rhs.first != MY_MAX));

    int P1_1 = Node::conditional_select(rhs.first, lhs.first, (cond1 && cond1_1) || (!cond1 && cond2_1));
    int P1_2 = Node::conditional_select(rhs.second, lhs.second, (cond1 && cond1_1) || (!cond1 && cond2_1));

    int P2_1 = Node::conditional_select(lhs.first, rhs.first, (cond1 && cond1_1) || (!cond1 && cond2_1));
    int P2_2 = Node::conditional_select(lhs.second, rhs.second, (cond1 && cond1_1) || (!cond1 && cond2_1));

    pair<int, int> P1(P1_1, P1_2);
    pair<int, int> P2(P2_1, P2_2);

    setToVisit(tovisit, i, P1);
    setToVisit(tovisit, j, P2);

    //    if (step == 1) {
    //        if (dir == ((lhs.first > rhs.first) || (BFS == false && lhs.first == rhs.first && rhs.second > lhs.second)
    //                || (BFS == true && lhs.first == rhs.first && rhs.second < lhs.second))) {
    //            setToVisit(tovisit, i, rhs);
    //            setToVisit(tovisit, j, lhs);
    //
    //        } else {
    //            setToVisit(tovisit, i, lhs);
    //            setToVisit(tovisit, j, rhs);
    //        }
    //    } else {
    //        if (dir == ((BFS == false && lhs.first != MY_MAX && rhs.first != MY_MAX && lhs.second != MY_MAX && rhs.second != MY_MAX && lhs.second < rhs.second) ||
    //                (BFS == true && lhs.first != MY_MAX && rhs.first != MY_MAX && lhs.second != MY_MAX && rhs.second != MY_MAX && lhs.second > rhs.second) ||
    //                (lhs.first != MY_MAX && rhs.first != MY_MAX && lhs.second == MY_MAX && rhs.second != MY_MAX) ||
    //                (lhs.first == MY_MAX && rhs.first != MY_MAX))) {
    //            setToVisit(tovisit, i, rhs);
    //            setToVisit(tovisit, j, lhs);
    //
    //        } else {
    //            setToVisit(tovisit, i, lhs);
    //            setToVisit(tovisit, j, rhs);
    //        }
    //    }
}

void bitonicMerge2(char** tovisit, int low, int cnt, bool dir, int step, bool BFS) {
    if (cnt > 1) {
        int k = cnt / 2;
        for (int i = low; i < low + k; i++) {
            compAndSwap2(tovisit, i, i + k, dir, step, BFS);
        }
        bitonicMerge2(tovisit, low, k, dir, step, BFS);
        bitonicMerge2(tovisit, low + k, k, dir, step, BFS);
    }
}

void bitonicSort2(char** tovisit, int low, int cnt, bool dir, int step, bool BFS) {
    if (cnt > 1) {
        int k = cnt / 2;
        bitonicSort2(tovisit, low, k, true, step, BFS);
        bitonicSort2(tovisit, low + k, k, false, step, BFS);
        bitonicMerge2(tovisit, low, cnt, dir, step, BFS);
    }
}

void ecall_oblivm_DFS(int src, char** tovisit, char** add) {
    for (int i = 0; i < vertexNumber; i++) {
        bool cond = Node::CTeq(i, src - 1);
        int firstPart = Node::conditional_select(src, MY_MAX, cond);
        int secondPart = Node::conditional_select(0, MY_MAX, cond);
        setToVisit(tovisit, i, pair<int, int>(firstPart, secondPart));

        //        if (i == src - 1) {
        //            setToVisit(tovisit, i, pair<int, int>(src, 0));
        //        } else {
        //            setToVisit(tovisit, i, pair<int, int>(MY_MAX, MY_MAX));
        //        }
        setAdd(add, i, pair<int, int>(MY_MAX, MY_MAX));
    }

    int maxPad = (int) pow(2, ceil(log2(vertexNumber * 2)));
    for (int i = vertexNumber; i < maxPad; i++) {
        setToVisit(tovisit, i, pair<int, int>(MY_MAX, MY_MAX));
    }

    for (int i = 0; i < vertexNumber; i++) {
        pair<int, int> curPair = getToVisit(tovisit, 0);
        int u = curPair.first;
        setToVisit(tovisit, 0, pair<int, int>(u, MY_MAX));

        printf("Node:%d Visisted\n", u);

        for (int j = 0; j < vertexNumber; j++) {
            string omapKey = "!" + to_string(u) + "-" + to_string(j + 1);
            string weight = readOMAP(omapKey);
            int firstPart = Node::conditional_select(MY_MAX, j + 1, Node::CTeq(weight.length(), 0));
            int secondPart = Node::conditional_select(MY_MAX, i + 1, Node::CTeq(weight.length(), 0));

            setAdd(add, j, pair<int, int>(firstPart, secondPart));
            //            if (weight != "") {
            //                setAdd(add, j, pair<int, int>(j + 1, i + 1));
            //            } else {
            //                setAdd(add, j, pair<int, int>(MY_MAX, MY_MAX));
            //            }
        }

        mergeAddAndTovisit(add, tovisit);

        bitonicSort2(tovisit, 0, maxPad, true, 1, false);

        int lastV = -1;
        for (int j = 0; j < vertexNumber * 2; j++) {
            pair<int, int> pvalues = getToVisit(tovisit, j);
            int firstPart = pvalues.first;
            int secondPart = pvalues.second;
            bool cond = Node::CTeq(lastV, firstPart);
            lastV = Node::conditional_select(firstPart, lastV, !cond);
            firstPart = Node::conditional_select(MY_MAX, firstPart, cond);
            secondPart = Node::conditional_select(MY_MAX, secondPart, cond);
            setToVisit(tovisit, j, pair<int, int>(firstPart, secondPart));
        }

        bitonicSort2(tovisit, 0, maxPad, true, 2, false);
    }
}

void ecall_oblivm_BFS(int src, char** tovisit, char** add) {
    for (int i = 0; i < vertexNumber; i++) {
        if (i == src - 1) {
            setToVisit(tovisit, i, pair<int, int>(src, 0));
        } else {
            setToVisit(tovisit, i, pair<int, int>(MY_MAX, MY_MAX));
        }
        setAdd(add, i, pair<int, int>(MY_MAX, MY_MAX));
    }

    int maxPad = (int) pow(2, ceil(log2(vertexNumber * 2)));
    for (int i = vertexNumber; i < maxPad; i++) {
        setToVisit(tovisit, i, pair<int, int>(MY_MAX, MY_MAX));
    }

    for (int i = 0; i < vertexNumber; i++) {
        pair<int, int> curPair = getToVisit(tovisit, 0);
        int u = curPair.first;
        setToVisit(tovisit, 0, pair<int, int>(u, MY_MAX));

        //        printf("Node:%d Visisted\n", u);

        for (int j = 0; j < vertexNumber; j++) {
            string omapKey = "!" + to_string(u) + "-" + to_string(j + 1);
            string weight = readOMAP(omapKey);
            if (weight != "") {
                setAdd(add, j, pair<int, int>(j + 1, i + 1));
            } else {
                setAdd(add, j, pair<int, int>(MY_MAX, MY_MAX));
            }
        }

        mergeAddAndTovisit(add, tovisit);

        bitonicSort2(tovisit, 0, maxPad, true, 1, true);

        int lastV = -1;
        for (int j = 0; j < vertexNumber * 2; j++) {
            if (lastV != getToVisit(tovisit, j).first) {
                lastV = getToVisit(tovisit, j).first;
                continue;
            } else {
                setToVisit(tovisit, j, pair<int, int>(MY_MAX, MY_MAX));
            }
        }

        bitonicSort2(tovisit, 0, maxPad, true, 2, true);
    }
}

void compAndSwap(char** edgeList, int i, int j, bool dir) {
    block ciphertext((*edgeList) + i*edgeStoreSingleBlockSize, (*edgeList)+ (i + 1) * edgeStoreSingleBlockSize);
    block buffer = AES::Decrypt(tmpkey, ciphertext, edgeClenSize);
    GraphNode* left = GraphNode::convertBlockToNode(buffer);

    block ciphertext2((*edgeList) + j*edgeStoreSingleBlockSize, (*edgeList)+ (j + 1) * edgeStoreSingleBlockSize);
    block buffer2 = AES::Decrypt(tmpkey, ciphertext2, edgeClenSize);
    GraphNode* right = GraphNode::convertBlockToNode(buffer2);

    bool cond = (Node::CTeq(Node::CTcmp(left->weight, right->weight), 1) && dir) || (!(Node::CTeq(Node::CTcmp(left->weight, right->weight), 1)) && !dir);
    Node::conditional_swap(left->src_id, right->src_id, static_cast<int>(cond));
    Node::conditional_swap(left->dst_id, right->dst_id, static_cast<int>(cond));
    Node::conditional_swap(left->weight, right->weight, static_cast<int>(cond));

    std::array<byte_t, sizeof (GraphNode) > data;
    const byte_t* begin = reinterpret_cast<const byte_t*> (std::addressof((*left)));
    const byte_t* end = begin + sizeof (GraphNode);
    std::copy(begin, end, std::begin(data));
    block buffer3(data.begin(), data.end());
    block ciphertext3 = AES::Encrypt(tmpkey, buffer3, edgeClenSize, edgeBlockSize);
    memcpy((uint8_t*) (*edgeList) + i * ciphertext3.size(), ciphertext3.data(), ciphertext3.size());

    std::array<byte_t, sizeof (GraphNode) > data2;
    const byte_t* begin2 = reinterpret_cast<const byte_t*> (std::addressof((*right)));
    const byte_t* end2 = begin2 + sizeof (GraphNode);
    std::copy(begin2, end2, std::begin(data2));
    block buffer4(data2.begin(), data2.end());
    block ciphertext4 = AES::Encrypt(tmpkey, buffer4, edgeClenSize, edgeBlockSize);
    memcpy((uint8_t*) (*edgeList) + j * ciphertext4.size(), ciphertext4.data(), ciphertext4.size());

    delete left;
    delete right;
}

void bitonicMerge(char** edgeList, int low, int cnt, bool dir) {
    if (cnt > 1) {
        int k = cnt / 2;
        for (int i = low; i < low + k; i++)
            compAndSwap(edgeList, i, i + k, dir);
        bitonicMerge(edgeList, low, k, dir);
        bitonicMerge(edgeList, low + k, k, dir);
    }
}

void bitonicSort(char** edgeList, int low, int cnt, bool dir) {
    if (cnt > 1) {
        int k = cnt / 2;
        bitonicSort(edgeList, low, k, true);
        bitonicSort(edgeList, low + k, k, false);
        bitonicMerge(edgeList, low, cnt, dir);
    }
}

string root(string x) {
    string id = readOMAP(string("/" + x));
    while (id != x) {
        string newId = readOMAP(string("/" + id));
        writeOMAP("/" + x, newId);
        id = newId;
        x = id;
        id = readOMAP(string("/" + x));
    }
    return x;
}

void ecall_oblivm_kruskal_minimum_spanning_tree(char** edgeList) {
    int maxPad = (int) pow(2, ceil(log2(edgeNumber)));
    bitonicSort(edgeList, 0, maxPad, true);
    int cnt = 0;

    for (int i = 1; i <= vertexNumber; i++) {
        writeOMAP("/" + to_string(i), to_string(i));
    }

    int state = 0;
    string x, id, srcRoot, dstRoot;
    GraphNode* node = NULL;

    while (cnt < edgeNumber) {
        if (state == 0) {
            block ciphertext((*edgeList) + cnt*edgeStoreSingleBlockSize, (*edgeList)+ (cnt + 1) * edgeStoreSingleBlockSize);
            block buffer = AES::Decrypt(tmpkey, ciphertext, edgeClenSize);
            GraphNode* node = GraphNode::convertBlockToNode(buffer);

            x = node->src_id;
            id = readOMAP(string("/" + x));
            readOMAP(string("/" + x));
            state = 1;
        } else if (state == 1) {
            if (id != x) {
                string newId = readOMAP(string("/" + id));
                writeOMAP("/" + x, newId);
                id = newId;
                x = id;
                id = readOMAP(string("/" + x));
                state = 1;
            } else {
                srcRoot = x;
                x = node->dst_id;
                id = readOMAP(string("/" + x));
                readOMAP(string("/" + x));
                state = 2;
            }
        } else if (state == 2) {
            if (id != x) {
                string newId = readOMAP(string("/" + id));
                writeOMAP("/" + x, newId);
                id = newId;
                x = id;
                id = readOMAP(string("/" + x));
                state = 2;
            } else {
                dstRoot = x;
                readOMAP(string("/0"));
                readOMAP(string("/0"));
                state = 3;
            }
        } else if (state == 3) {
            if (srcRoot != dstRoot) {
                id = readOMAP(string("/" + dstRoot));
                writeOMAP("/" + srcRoot, id);
                //            printf("%s to %s with weight %d\n", node->src_id, node->dst_id, node->weight);
                state = 0;
                cnt++;
                delete node;
            } else {
                readOMAP("/" + srcRoot);
                readOMAP("/" + srcRoot);
                state = 0;
                cnt++;
                delete node;
            }
        }
    }
}

void ecall_kruskal_minimum_spanning_tree(char** edgeList) {
    int maxPad = (int) pow(2, ceil(log2(edgeNumber)));
    bitonicSort(edgeList, 0, maxPad, true);
    int cnt = 0;

    for (int i = 1; i <= vertexNumber; i++) {
        writeOMAP("/" + to_string(i), to_string(i));
    }

    while (cnt < edgeNumber) {
        block ciphertext((*edgeList) + cnt*edgeStoreSingleBlockSize, (*edgeList)+ (cnt + 1) * edgeStoreSingleBlockSize);
        block buffer = AES::Decrypt(tmpkey, ciphertext, edgeClenSize);
        GraphNode* node = GraphNode::convertBlockToNode(buffer);

        string srcRoot = root(to_string(node->src_id));
        string dstRoot = root(to_string(node->dst_id));

        if (srcRoot != dstRoot) {
            //            string id = readOMAP(string("/" + dstRoot));
            //            writeOMAP("/" + srcRoot, id);
            writeOMAP("/" + srcRoot, dstRoot);
            printf("%d to %d with weight %d\n", node->src_id, node->dst_id, node->weight);
        } else {
            readOMAP("/" + srcRoot);
        }
        cnt++;
        delete node;
    }
}

void ecall_oblivious_kruskal_minimum_spanning_tree(char** edgeList) {
    int maxPad = (int) pow(2, ceil(log2(edgeNumber)));
    bitonicSort(edgeList, 0, maxPad, true);

    //    for (int i = 1; i <= vertexNumber; i++) {
    //        writeOMAP("/" + to_string(i), to_string(i));
    //    }

    int i = 0, st = 1;
    string vertex = "", curRoot = "", newRoot = "", init_root = "", trm_root = "";
    int upperBound = edgeNumber * int(log2(vertexNumber))*2;
    for (int j = 0; j < upperBound; j++) {
        if (j % 100 == 0) {
            printf("%d/%d\n", j, upperBound);
        }
        int index = Node::conditional_select(i, maximumPad, Node::CTeq(Node::CTcmp(i, maximumPad), -1));
        //        int index = i < (vertexNumber * 2) ? i : vertexNumber * 2;

        block ciphertext((*edgeList) + (int) floor(index / 2) * edgeStoreSingleBlockSize, (*edgeList)+ ((int) floor(index / 2) + 1) * edgeStoreSingleBlockSize);
        block buffer = AES::Decrypt(tmpkey, ciphertext, edgeClenSize);
        GraphNode* node = GraphNode::convertBlockToNode(buffer);

        vertex = CTString(to_string(node->src_id), vertex, (Node::CTeq(st, 1) && Node::CTeq(i % 2, 0)));
        //        vertex = (st == 1 && i % 2 == 0) ? to_string(node->src_id) : vertex;
        vertex = CTString(to_string(node->dst_id), vertex, (Node::CTeq(st, 1) && Node::CTeq(i % 2, 1)));
        //        vertex = (st == 1 && i % 2 == 1) ? to_string(node->dst_id) : vertex;
        string tmp = readOMAP(string("/" + vertex));
        curRoot = CTString(tmp, curRoot, Node::CTeq(st, 1));
        //        curRoot = st == 1 ? tmp : curRoot;
        st = Node::conditional_select(2, 1, !CTeq(curRoot, vertex));
        //        st = (curRoot != vertex) ? 2 : 1;

        tmp = readOMAP(string("/" + curRoot));
        newRoot = CTString(tmp, newRoot, Node::CTeq(st, 2));
        //        newRoot = (st == 2 ? tmp : newRoot);
        string mapKey = CTString(vertex, "0", Node::CTeq(st, 2));
        //        string mapKey = (st == 2 ? vertex : "-1");
        readWriteOMAP("/" + mapKey, newRoot);
        curRoot = CTString(newRoot, curRoot, Node::CTeq(st, 2));
        //        curRoot = (st == 2 ? newRoot : curRoot);
        vertex = CTString(curRoot, vertex, Node::CTeq(st, 2));
        //        vertex = (st == 2 ? curRoot : vertex);
        tmp = readOMAP(string("/" + vertex));
        curRoot = CTString(tmp, curRoot, Node::CTeq(st, 2));
        //        curRoot = (st == 2 ? tmp : curRoot);

        init_root = CTString(vertex, init_root, Node::CTeq(st, 1) && Node::CTeq(i % 2, 0));
        //        init_root = (st == 1 && i % 2 == 0) ? vertex : init_root;
        trm_root = CTString(vertex, trm_root, Node::CTeq(st, 1) && Node::CTeq(i % 2, 1));
        //        trm_root = (st == 1 && i % 2 == 1) ? vertex : trm_root;
        mapKey = CTString(init_root, "0", Node::CTeq(st, 1) && Node::CTeq(i % 2, 1) && !CTeq(init_root, trm_root));
        //        mapKey = (st == 1 && i % 2 == 1 && init_root != trm_root) ? init_root : "-1";

        if (mapKey != "0") {
            printf("%s to %s with weight %d\n", to_string(node->src_id).c_str(), to_string(node->dst_id).c_str(), node->weight);
        }

        readWriteOMAP("/" + mapKey, trm_root);
        i = Node::conditional_select(i + 1, i, Node::CTeq(st, 1));
        delete node;
        //        i = (st == 1 ? i + 1 : i);
    }
}

int minDistance() {
    // Initialize min value 
    int min = INT_MAX;
    int min_index = -1;

    for (int v = 1; v <= vertexNumber; v++) {
        auto parts = splitData(readOMAP("/" + to_string(v)), "-");
        string sptSet = parts[1];
        int distV = stoi(parts[0]);
        if (sptSet == "0" && distV <= min) {
            min = distV;
            min_index = v;
        }
    }
    return min_index;
}

//SSSP with scn of vertext list

void ecall_single_source_shortest_path(int src) {
    for (int i = 1; i <= vertexNumber; i++) {
        writeOMAP("/" + to_string(i), to_string(INT_MAX) + "-0");
    }

    writeOMAP("/" + to_string(src), "0-0"); //dist[src] = 0

    for (int count = 1; count < vertexNumber; count++) {
        int u = minDistance();

        readSetOMAP("/" + to_string(u));

        for (int v = 1; v <= vertexNumber; v++) {

            string vData = readOMAP("/" + to_string(v));
            auto tmpParts = splitData(vData, "-");
            string sptSet = tmpParts[1];
            int distU = stoi(splitData(readOMAP("/" + to_string(u)), "-")[0]);
            int distV = stoi(tmpParts[0]);
            string edge = readOMAP("!" + to_string(u) + "-" + to_string(v));
            int weight = -1;
            if (edge != "") {
                vector<string> parts = splitData(edge, "-");
                weight = stoi(parts[0]);
            }

            if (sptSet == "0" && edge != "" && distU != INT_MAX && distU + weight < distV) {
                writeOMAP("/" + to_string(v), to_string(distU + weight) + "-0");
            }
        }
    }

    // uncommented to see traversal
    printf("Vertex   Distance from Source\n");
    for (int i = 1; i <= vertexNumber; i++){
        printf("%d tt %s\n", i, readOMAP("/" + to_string(i)).c_str());
    }
}

//SSSP with min heap

void ecall_efficient_single_source_shortest_path(int src) {
    //    ObliviousMinHeap* minHeap = new ObliviousMinHeap(vertexNumber);
    //
    //    for (int i = 1; i <= vertexNumber; i++) {
    //        writeOMAP("/" + to_string(i), to_string(MY_MAX));
    //        minHeap->setNewMinHeapNode(i - 1, i - 1, MY_MAX);
    //    }
    //
    //    writeOMAP("/" + to_string(src), "0");
    //    minHeap->decreaseKey(src - 1, 0);
    //
    //    while (!minHeap->isEmpty()) {
    //        int u = (minHeap->extractMinID() + 1);
    //        int cnt = 1;
    //        string omapKey = "$" + to_string(u) + "-" + to_string(cnt);
    //        string dstStr = readOMAP(omapKey);
    //
    //        while (dstStr != "") {
    //            auto parts = splitData(dstStr, "-");
    //            int v = stoi(parts[0]);
    //            int weight = stoi(parts[1]);
    //
    //            int distU = stoi(readOMAP("/" + to_string(u)));
    //            int distV = stoi(readOMAP("/" + to_string(v)));
    //
    //            if (minHeap->isInMinHeap(v - 1) && distU != MY_MAX && weight + distU < distV) {
    //                writeOMAP("/" + to_string(v), to_string(distU + weight));
    //                minHeap->decreaseKey(v - 1, distU + weight);
    //            }
    //            cnt++;
    //            omapKey = "$" + to_string(u) + "-" + to_string(cnt);
    //            dstStr = readOMAP(omapKey);
    //        }
    //    }

    //    printf("Vertex   Distance from Source\n");
    //    for (int i = 1; i <= vertexNumber; i++) {
    //        printf("%d tt %s\n", i, readOMAP("/" + to_string(i)).c_str());
    //    }
}

//SSSP with oblivm version min heap

void ecall_oblivm_single_source_shortest_path(int src) {
    ecall_setup_oheap(edgeNumber);

    ocall_start_timer(34);
    for (int i = 1; i <= vertexNumber; i++) {
        writeOMAP("/" + to_string(i), to_string(MY_MAX));
    }

    writeOMAP("/" + to_string(src), "0");
    ecall_set_new_minheap_node(src - 1, 0);

    bool innerloop = false;
    string dstStr, omapKey;
    int u = -1, cnt = 1, distu = -1, curDistU = -1;

    for (int i = 0; i < (2 * vertexNumber + edgeNumber); i++) {
        if (i % 10 == 0) {
            printf("%d/%d\n", i, vertexNumber + edgeNumber);
        }
        if (innerloop == false) {
            u = -1;
            distu = -1;
            ecall_extract_min_id(&u, &distu);
            if (u == -1) {
                u = u;
                curDistU = -2;
            } else {
                u++;
                string readData = readOMAP("/" + to_string(u));
                curDistU = stoi(readData);
            }

            if (curDistU == distu) {
                cnt = 1;
                omapKey = "$" + to_string(u) + "-" + to_string(cnt);
                dstStr = readOMAP(omapKey);
                if (dstStr != "") {
                    innerloop = true;
                } else {
                    innerloop = false;
                }
            } else {
                writeOMAP("/-", "");
            }
            writeOMAP("/-", "");
        } else {
            auto parts = splitData(dstStr, "-");
            int v = stoi(parts[0]);
            int weight = stoi(parts[1]);
            int distU = curDistU;
            int distV = stoi(readOMAP("/" + to_string(v)));

            if (weight + distU < distV) {
                writeOMAP("/" + to_string(v), to_string(distU + weight));
                ecall_set_new_minheap_node(v - 1, distU + weight);
            } else {
                writeOMAP("/-", "");
                ecall_dummy_heap_op();
            }
            cnt++;
            omapKey = "$" + to_string(u) + "-" + to_string(cnt);
            dstStr = readOMAP(omapKey);
            if (dstStr != "") {
                innerloop = true;
            } else {
                innerloop = false;
            }
        }
    }

    //    printf("Vertex   Distance from Source\n");
    //    for (int i = 1; i <= vertexNumber; i++) {
    //        printf("%d tt %s\n", i, readOMAP("/" + to_string(i)).c_str());
    //    }
}

void ecall_oblivious_oblivm_single_source_shortest_path(int src) {
    ecall_setup_oheap(edgeNumber);

    ocall_start_timer(34);


    readWriteOMAP("/" + to_string(src), "0");
    ecall_set_new_minheap_node(src - 1, 0);

    bool innerloop = false;
    string dstStr, omapKey;
    int u = -1, cnt = 1, distu = -1, distv = -1, v = -1, curDistU = -1, weight = -1;
    string mapKey = "", mapValue = "", tmp = "";

    for (int i = 0; i < (2 * vertexNumber + edgeNumber); i++) {
        if (i % 10 == 0) {
            printf("%d/%d\n", i, 2 * vertexNumber + edgeNumber);
        }
        bool check = Node::CTeq(dstStr.length(), 0) && !innerloop;
        dstStr = CTString("0-0", dstStr, check);
        auto parts = splitData(dstStr, "-");
        v = Node::conditional_select(stoi(parts[0]), v, innerloop);
        //        v = innerloop ? stoi(parts[0]) : v;
        weight = Node::conditional_select(stoi(parts[1]), weight, innerloop);
        //        weight = innerloop ? stoi(parts[1]) : weight;       //TODO
        distu = Node::conditional_select(curDistU, -1, innerloop);
        //        distu = innerloop ? curDistU : -1;

        mapKey = CTString(to_string(v), "0", innerloop);
        //        mapKey = innerloop ? to_string(v) : "-";
        u = Node::conditional_select(u, -1, innerloop);
        //        u = innerloop ? u : -1;
        tmp = readOMAP("/" + to_string(v));

        check = Node::CTeq(tmp.length(), 0) && !innerloop;
        tmp = CTString("0-0", tmp, check);
        distv = Node::conditional_select(stoi(tmp), distv, innerloop);
        //        distv = innerloop ? stoi(tmp) : distv;
        mapValue = CTString(to_string(distu + weight), to_string(distv), innerloop && Node::CTeq(Node::CTcmp(distu + weight, distv), -1));
        //        mapValue = (innerloop && (distu + weight < distv)) ? to_string(distu + weight) : to_string(distv);
        readWriteOMAP("/" + mapKey, mapValue);

        int heapOp = 3;
        heapOp = Node::conditional_select(1, heapOp, !innerloop);
        heapOp = Node::conditional_select(2, heapOp, innerloop && Node::CTeq(Node::CTcmp(distu + weight, distv), -1));

        int heapV = u;
        int heapDist = distu;
        heapV = Node::conditional_select(v - 1, heapV, innerloop && Node::CTeq(Node::CTcmp(distu + weight, distv), -1));
        heapDist = Node::conditional_select(distu + weight, heapDist, innerloop && Node::CTeq(Node::CTcmp(distu + weight, distv), -1));

        ecall_execute_heap_operation(&heapV, &heapDist, heapOp);

        u = Node::conditional_select(heapV, u, !innerloop);
        distu = Node::conditional_select(heapDist, distu, !innerloop);

        //        if (innerloop == false) {
        //            ecall_extract_min_id(&u, &distu);
        //        } else if (innerloop && (distu + weight < distv)) {
        //            ecall_set_new_minheap_node(v - 1, distu + weight);
        //        } else {
        //            ecall_dummy_heap_op();
        //        }
        cnt = Node::conditional_select(cnt + 1, cnt, innerloop);
        //        cnt = innerloop ? cnt + 1 : cnt;
        u = Node::conditional_select(u + 1, u, !innerloop && !Node::CTeq(u, -1));
        mapKey = CTString(to_string(u), "0", !innerloop && !Node::CTeq(u, -1));
        //        mapKey = ((innerloop == false) && u != -1) ? to_string(++u) : "-";
        tmp = readOMAP("/" + mapKey);

        check = Node::CTeq(tmp.length(), 0) && (innerloop || Node::CTeq(u, -1));
        tmp = CTString("0-0", tmp, check);
        curDistU = Node::conditional_select(stoi(tmp), curDistU, !innerloop && !Node::CTeq(u, -1));
        //        curDistU = ((innerloop == false) && u != -1) ? stoi(tmp) : curDistU;
        curDistU = Node::conditional_select(-2, curDistU, !innerloop && Node::CTeq(u, -1));
        //        curDistU = ((innerloop == false) && u == -1) ? -2 : curDistU;
        cnt = Node::conditional_select(1, cnt, !innerloop && Node::CTeq(curDistU, distu));
        //        cnt = (innerloop == false && curDistU == distu) ? 1 : cnt;
        tmp = readOMAP("$" + to_string(u) + "-" + to_string(cnt));

        dstStr = CTString(tmp, dstStr, innerloop || Node::CTeq(curDistU, distu));
        //        dstStr = (innerloop || curDistU == distu) ? tmp : dstStr;

        innerloop = (innerloop && !Node::CTeq(dstStr.length(), 0)) || (!innerloop && Node::CTeq(curDistU, distu) && !Node::CTeq(dstStr.length(), 0));
        //        innerloop = (innerloop && dstStr != "") || (innerloop == false && curDistU == distu && dstStr != "") ? true : false;
    }

    printf("Vertex Distance from Source\n");
    for (int i = 1; i <= vertexNumber; i++) {
        printf("Destination:%d  Distance:%s\n", i, readOMAP("/" + to_string(i)).c_str());
    }
}