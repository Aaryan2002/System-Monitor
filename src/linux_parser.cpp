#include <dirent.h>
#include <unistd.h>
#include <string>
#include <vector>
#include <unistd.h>
#include "linux_parser.h"

using std::stof;
using std::string;
using std::to_string;
using std::vector;

// DONE: An example of how to read data from the filesystem
string LinuxParser::OperatingSystem() {
  string line;
  string key;
  string value;
  std::ifstream filestream(kOSPath);
  if (filestream.is_open()) {
    while (std::getline(filestream, line)) {
      std::replace(line.begin(), line.end(), ' ', '_');
      std::replace(line.begin(), line.end(), '=', ' ');
      std::replace(line.begin(), line.end(), '"', ' ');
      std::istringstream linestream(line);
      while (linestream >> key >> value) {
        if (key == "PRETTY_NAME") {
          std::replace(value.begin(), value.end(), '_', ' ');
          return value;
        }
      }
    }
  }
  return value;
}

// DONE: An example of how to read data from the filesystem
string LinuxParser::Kernel() {
  string os, version, kernel;
  string line;
  std::ifstream stream(kProcDirectory + kVersionFilename);
  if (stream.is_open()) {
    std::getline(stream, line);
    std::istringstream linestream(line);
    linestream >> os >> version >> kernel;
  }
  return kernel;
}

// BONUS: Update this to use std::filesystem
vector<int> LinuxParser::Pids() {
  vector<int> pids;
  DIR* directory = opendir(kProcDirectory.c_str());
  struct dirent* file;
  while ((file = readdir(directory)) != nullptr) {
    // Is this a directory?
    if (file->d_type == DT_DIR) {
      // Is every character of the name a digit?
      string filename(file->d_name);
      if (std::all_of(filename.begin(), filename.end(), isdigit)) {
        int pid = stoi(filename);
        pids.push_back(pid);
      }
    }
  }
  closedir(directory);
  return pids;
}

// TODO: Read and return the system memory utilization
float LinuxParser::MemoryUtilization() { 
  string line;
  long MemTotal,MemFree;
  string varName; 
  long MemUsed = 0; //Represents the total memory used = MemTotal- MemFree
  std::ifstream stream (kProcDirectory+kMeminfoFilename);
  if (stream.is_open()){
    
    std::getline(stream,line);
    std::istringstream linestream(line);
    linestream>>varName>>MemTotal;
    std::getline(stream,line);
    std::istringstream linestream2(line);
    linestream>>varName>>MemFree;
    MemUsed = MemTotal - MemFree;
    return ((MemUsed/MemTotal) * 100.0); // returns percentage of used memory
  }
  
  return 0.0; }

// TODO: Read and return the system uptime
long LinuxParser::UpTime() { 
  long upTime;
  string line;
  std::ifstream stream (kProcDirectory+kUptimeFilename);
  if (stream.is_open()){
    std::getline(stream,line);
    std::istringstream linestream(line);
    linestream>>upTime;
    return upTime;
  }
  return 0; }

// TODO: Read and return the number of jiffies for the system
long LinuxParser::Jiffies() {
  string line;
  long jiffies = 0;
  long jiff;
  string cpu;
  std::ifstream stream (kProcDirectory+kStatFilename);
  if (stream.is_open()){
     std::getline(stream,line);
     std::istringstream linestream(line);
     linestream>>cpu;
    for(int i = 0;i<8;i++){
       linestream>>jiff;
       jiffies+=jiff; 
    }
    return jiffies;
    }
  return 0; }

// TODO: Read and return the number of active jiffies for a PID
// REMOVE: [[maybe_unused]] once you define the function
long LinuxParser::ActiveJiffies(int pid) {
    string line;
  string jiff;
  long activejiffies = 0;
  std::ifstream stream(kProcDirectory+std::to_string(pid)+kStatFilename);
if (stream.is_open()){
  std::getline(stream,line);
  std::istringstream linestream(line);
  for(int i =0;i<14;i++){
    linestream>>jiff;
  }
  for(int i =0;i<4;i++){
    activejiffies += std::stol(jiff);
    linestream>>jiff;
  }
  return activejiffies;
}  
  return 0; }

// TODO: Read and return the number of active jiffies for the system
long LinuxParser::ActiveJiffies() { 
 long active_jiffies = LinuxParser::Jiffies() - LinuxParser::IdleJiffies();
return active_jiffies;
}

// TODO: Read and return the number of idle jiffies for the system
long LinuxParser::IdleJiffies() {
  string line;
  long idle_jiffies=0;
  long jiff;
  string cpu;
  std::ifstream stream (kProcDirectory+kStatFilename);
  if (stream.is_open()){
    std::getline(stream,line);
    std::istringstream linestream(line);
    linestream>>cpu;
    for (int i = 0;i<4;i++){
      linestream>>jiff;
    }
    idle_jiffies += jiff;
    linestream>>jiff;
    idle_jiffies += jiff;
    return idle_jiffies;
  }
  return 0; }

// TODO: Read and return CPU utilization
float LinuxParser::CpuUtilization(int pid) { 
  long seconds = LinuxParser::UpTime() - LinuxParser::UpTime(pid);
  float cpuUtil = ( LinuxParser::ActiveJiffies(pid)/sysconf(_SC_CLK_TCK))/seconds;
  return cpuUtil;
}
float LinuxParser::CpuUtilization(){
float cpuUtil = LinuxParser::ActiveJiffies()/(LinuxParser::Jiffies());
return cpuUtil;
}


// TODO: Read and return the total number of processes
int LinuxParser::TotalProcesses() { 
  string line,key;
  long tot_processes;
  std::ifstream stream (kProcDirectory +kStatFilename);
  if (stream.is_open()){
    while(std::getline(stream,line)){
      std::istringstream linestream(line);
      linestream>>key;
      if (key == "processes"){
        linestream>>tot_processes;
        return tot_processes;
      }   
    }
  }
  return 0; }

// TODO: Read and return the number of running processes
int LinuxParser::RunningProcesses() {
  string line,key;
  long run_processes;
  std::ifstream stream (kProcDirectory +kStatFilename);
  if (stream.is_open()){
    while(std::getline(stream,line)){
      std::istringstream linestream(line);
      linestream>>key;
      if (key == "procs_running"){
        linestream>>run_processes;
        return run_processes;
      }   
    }
  }
  return 0; }

// TODO: Read and return the command associated with a process
// REMOVE: [[maybe_unused]] once you define the function
string LinuxParser::Command(int pid) {
  string command;
  std::ifstream stream(kProcDirectory + std::to_string(pid) + kCmdlineFilename);
  if (stream.is_open()){
    std::getline(stream,command);
    return command;
  }
  return string(); }

// TODO: Read and return the memory used by a process
// REMOVE: [[maybe_unused]] once you define the function
string LinuxParser::Ram(int pid) { 
  string line,key;
  string ram;
  std::ifstream stream (kProcDirectory + std::to_string(pid) +kStatusFilename);
  if (stream.is_open()){
    while(std::getline(stream,line)){
      std::istringstream linestream(line);
      linestream>>key;
      if (key == "VmSize:"){
        linestream>>ram;
        return ram;
      }   
    }
  }
  
  return string(); }

// TODO: Read and return the user ID associated with a process
// REMOVE: [[maybe_unused]] once you define the function
string LinuxParser::Uid(int pid) {
  string line,key;
  string uid;
  std::ifstream stream (kProcDirectory + std::to_string(pid) +kStatusFilename);
  if (stream.is_open()){
    while(std::getline(stream,line)){
      std::istringstream linestream(line);
      linestream>>key;
      if (key == "Uid:"){
        linestream>>uid;
        return uid;
      }   
    }
  }
  
  return string(); }

// TODO: Read and return the user associated with a process
// REMOVE: [[maybe_unused]] once you define the function
string LinuxParser::User(int pid){ 
  string user,uid,x,_uid;
  string line;
  uid = LinuxParser::Uid(pid);
  std::ifstream stream (kPasswordPath);
  if (stream.is_open()){
    while (std::getline(stream,line)){
      std::replace(line.begin(), line.end(), ':', ' ');
      std::istringstream linestream(line);
      linestream>>user>>x>>_uid;
      if(_uid == uid){
        return user;
      }
    }
  } 
  
  return string(); }

// TODO: Read and return the uptime of a process
// REMOVE: [[maybe_unused]] once you define the function
long LinuxParser::UpTime(int pid) {
  string line;
  string uptime;
  std::ifstream stream(kProcDirectory+std::to_string(pid)+kStatFilename);
if (stream.is_open()){
  std::getline(stream,line);
  std::istringstream linestream(line);
  for(int i =0;i<22;i++){
    linestream>>uptime;
  }
  return std::stol(uptime)/sysconf(_SC_CLK_TCK);
}  
  return 0; }
