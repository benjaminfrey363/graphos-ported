#ifndef _ENCLAVE_H_
#define _ENCLAVE_H_

#include <stdlib.h>
#include <assert.h>
#include <stdarg.h>
#include <stdio.h>
#include <vector>
#include <array>
#include <string>

// Use the one, true canonical Types.h
#include "../../include/OMAP/Types.h"

// Bring common std types into the global namespace for this header
using std::string;
using std::vector;
using std::pair;

// Define the block type alias
using block = std::vector<uint8_t>;

#define ASC 0
#define DSC 1

//----------------------------------------------------------------------
// Global Variable Declarations
// 'extern' tells other files that these variables exist and are defined in enclave.cpp
//----------------------------------------------------------------------
extern int vertexNumber;
extern int edgeNumber;
extern bytes<Key> tmpkey;
extern unsigned long long edgeStoreSingleBlockSize;
extern unsigned long long storeSingleBlockSize;
extern unsigned long long pairStoreSingleBlockSize;

//----------------------------------------------------------------------
// Function Declarations (Prototypes)
//----------------------------------------------------------------------
void check_memory4(string text);
string readOMAP(string omapKey);
void writeOMAP(string omapKey, string omapValue);
string readWriteOMAP(string omapKey, string omapValue);
string readSetOMAP(string omapKey);
vector<string> naiveSplitData(const string& str, const string& delim);
vector<string> splitData(const string& str, const string& delim);
void addKeyValuePair(string key, string value, bytes<Key> secretKey);

// Ecall function declarations (now just regular functions)
void ecall_pad_nodes(char** edgeList);
void ecall_setup_with_small_memory(int eSize, long long vSize, const char* secretKey, char** edgeList, int op);
void ecall_del_node(const char* data);
void ecall_search_node(const char* data);
void ecall_add_node(const char* data, char** edgeList);
void ecall_PageRank();
void ecall_BFS(int src);
void ecall_non_oblivious_BFS(int src);
void ecall_oblivious_BFS(int src);
void ecall_DFS(int src);
void ecall_oblivm_DFS(int src, char** tovisit, char** add);
void ecall_oblivm_BFS(int src, char** tovisit, char** add);
void ecall_single_source_shortest_path(int src);
void ecall_efficient_single_source_shortest_path(int src);
void ecall_oblivm_single_source_shortest_path(int src);
void ecall_oblivious_oblivm_single_source_shortest_path(int src);
void ecall_kruskal_minimum_spanning_tree(char** edgeList);
void ecall_oblivious_kruskal_minimum_spanning_tree(char** edgeList);
void ecall_oblivm_kruskal_minimum_spanning_tree(char** edgeList);

// Utility and algorithm functions
string CTString(string a, string b, int choice);
bool CTeq(string a, string b);
pair<int, int> getToVisit(char** tovisit, int index);
void setToVisit(char** tovisit, int index, pair<int, int> data);
void setAdd(char** add, int index, pair<int, int> data);
void mergeAddAndTovisit(char** add, char** tovisit);
void compAndSwap2(char** tovisit, int i, int j, bool dir, int step, bool BFS);
void bitonicMerge2(char** tovisit, int low, int cnt, bool dir, int step, bool BFS);
void bitonicSort2(char** tovisit, int low, int cnt, bool dir, int step, bool BFS);
void compAndSwap(char** edgeList, int i, int j, bool dir);
void bitonicMerge(char** edgeList, int low, int cnt, bool dir);
void bitonicSort(char** edgeList, int low, int cnt, bool dir);
string root(string x);
int minDistance();

#endif /* !_ENCLAVE_H_ */