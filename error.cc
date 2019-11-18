#include "error.h"

#include <cstring>
#include <iostream>
#include <sstream>

#include "mbedtls/error.h"

// log file name may be up to 127 chars
char g_mbedtlsplusplus_logfile[] =
"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"
"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"
"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"
"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";

void logError(std::string the_message)
{
  std::string full_line = buildError(the_message);
  if(g_mbedtlsplusplus_logfile[0])
  {
    FILE* log_writer = fopen(g_mbedtlsplusplus_logfile, "at");
    fwrite(full_line.c_str(), 1, full_line.length(), log_writer);
    fclose(log_writer);
  }
  else
    std::cerr << full_line << std::endl;
}

//If you never call this, errors will just be logged to stderr.
void setLogFile(const char* logfile)
{
  strncpy(g_mbedtlsplusplus_logfile, logfile, 127);
}

std::string buildError(std::string the_message)
{
  time_t tempTime;
  time(&tempTime);
  std::string time_string(ctime(&tempTime));
  int newline_ind = time_string.find_first_of('\n');
  if(newline_ind != std::string::npos)
    time_string.erase(newline_ind);
  return time_string+": "+the_message+"\n";
}

std::string errorFromMbedTLSCode(std::string extra_comment,
                                                int code)
{
  char errbuf[300];
  mbedtls_strerror(code, errbuf, 300);

  std::stringstream ss;
  ss << std::hex << -code;

  return extra_comment + ": Error code -0x"+ss.str()+":\n"+std::string(errbuf);
}

void logErrorFromMbedTLSCode(std::string extra_comment, int code)
{
  logError(errorFromMbedTLSCode(extra_comment, code));
}
