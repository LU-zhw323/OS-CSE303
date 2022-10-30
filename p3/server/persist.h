#pragma once

#include <string>
#include <vector>

/// The purpose of this file is to allow you to declare helper functions that
/// simplify interacting with persistent storage.
/**
 * Helper function to generate the kv log
 * @param tag tag for log
 * @param key key 
 * @param val value
 * 
 * @return return a vector of log
*/
std::vector<uint8_t> log_kvblock(std::string tag,const std::string &key, const std::vector<uint8_t> &val);

/**
 * Helper function to generate the auth log
 * @param tag tag for log
 * 
 */

//Helper function to take a vector and put its size into a vector<uint8_t>
  ///@param v vector to get it size
  ///@return a vector contain the size
std::vector<uint8_t> size_block(std::vector<uint8_t> block);