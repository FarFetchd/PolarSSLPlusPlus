#ifndef MBEDTLSPLUSPLUS_ERROR_H_
#define MBEDTLSPLUSPLUS_ERROR_H_

#include <string>

extern char g_mbedtlsplusplus_logfile[];

void logError(std::string the_message);

//If you never call this, errors will just be logged to stderr.
void setLogFile(const char* log_file);

//Prepend a time
std::string buildError(std::string the_message);

std::string errorFromMbedTLSCode(std::string extra_comment, int code);

void logErrorFromMbedTLSCode(std::string extra_comment, int code);

#endif // MBEDTLSPLUSPLUS_ERROR_H_
