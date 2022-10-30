#include <cstdio>
#include <string>
#include <unistd.h>
#include <vector>
#include <stdio.h>
#include <string.h>

#include "persist.h"
#include "format.h"

using namespace std;

/// The purpose of this file is to allow you to define helper functions that
/// simplify interacting with persistent storage.
/**
 * Helper function to generate the kv log
 * @param tag tag for log
 * @param key key 
 * @param val value
 * 
 * @return return a vector of log
*/
std::vector<uint8_t> log_kvblock(std::string tag,const std::string &key, const std::vector<uint8_t> &val){
    std::vector<uint8_t> res;
    res.insert(res.end(), tag.begin(), tag.end());
    std::vector<uint8_t> key_block;
    key_block.assign(key.begin(), key.end());
    std::vector<uint8_t> key_sblock = size_block(key_block);
    res.insert(res.end(),key_sblock.begin(), key_sblock.end());
    res.insert(res.end(), key_block.begin(), key_block.end());
    if(strcmp(tag.c_str(),KVDELETE.c_str()) == 0){
        while(res.size()%8!=0){
            res.push_back('\0');
        }
        return res;
    }
    std::vector<uint8_t> val_sblock = size_block(val);
    res.insert(res.end(), val_sblock.begin(), val_sblock.end());
    res.insert(res.end(), val.begin(), val.end());
    while(res.size()%8!=0){
            res.push_back('\0');
        }
        return res;
}


//Helper function to take a vector and put its size into a vector<uint8_t>
///@param v vector to get it size
///@return a vector contain the size
std::vector<uint8_t> size_block(std::vector<uint8_t> block){
    size_t size = block.size();
    std::vector<uint8_t> sizeB(sizeof(size));
    memcpy(sizeB.data(), &size, sizeof(size));
    return sizeB;
}