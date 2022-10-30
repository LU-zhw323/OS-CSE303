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



/**
 * Helper function to generate the auth log
 * @param tag tag for log
 * @param user username
 * @param password password
 * @param content content
 * 
 * @return return a vector of log
 */
std::vector<uint8_t> log_authblock(std::string tag,const std::string &user, std::vector<uint8_t> salt, const std::vector<uint8_t> &pass, const std::vector<uint8_t> &content){
    std::vector<uint8_t> res;
    res.insert(res.end(), tag.begin(), tag.end());
    std::vector<uint8_t> user_block;
    user_block.assign(user.begin(), user.end());
    std::vector<uint8_t> user_sblock = size_block(user_block);
    res.insert(res.end(),user_sblock.begin(), user_sblock.end());
    res.insert(res.end(), user_block.begin(), user_block.end());
    //For Entry
    if(strcmp(tag.c_str(),AUTHENTRY.c_str()) == 0){
        std::vector<uint8_t> salt_sblock = size_block(salt);
        res.insert(res.end(),salt_sblock.begin(), salt_sblock.end());
        res.insert(res.end(), salt.begin(), salt.end());
        std::vector<uint8_t> pass_sblock = size_block(pass);
        res.insert(res.end(),pass_sblock.begin(), pass_sblock.end());
        res.insert(res.end(), pass.begin(), pass.end());
        size_t content_size = content.size();
        std::vector<uint8_t> content_sblock = size_block(content);
        res.insert(res.end(), content_sblock.begin(), content_sblock.end());
        if(content_size > 0){
            res.insert(res.end(),content.begin(),content.end());
        }
         while(res.size()%8!=0){
            res.push_back('\0');
        }
    }
    //For Dif
    else{
        size_t content_size = content.size();
        std::vector<uint8_t> content_sblock = size_block(content);
        res.insert(res.end(), content_sblock.begin(), content_sblock.end());
        res.insert(res.end(),content.begin(),content.end());
         while(res.size()%8!=0){
            res.push_back('\0');
        }
    }
    return res;
}