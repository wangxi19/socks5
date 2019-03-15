#ifndef TOOLS_H
#define TOOLS_H

#include <chrono>
#include <thread>
#include <string>
#include <string.h>
#include <mutex>
#include <future>
#include <list>
#include <initializer_list>

#ifdef _WIN32
#include <Windows.h>
#endif
#include <cctype>
#include <algorithm>

namespace MARKTOOLS {
#if TODO
	class MTimer {

	public:
		explicit MTimer(const std::chrono::seconds& timeout) {

		}

		~MTimer() {
			if (nullptr != exitSignal) {
				exitSignal->set_value();
				delete exitSignal;
			}
		}

		void doWork() {

		}

		void start() {
			if (nullptr != MThread) {
				exitSignal->set_value();
				delete exitSignal;
				exitSignal = new std::promise<void>;
				std::future<void> futureObj = exitSignal->get_future();
				MThread = new std::thread([this](std::future<void> futureObj) {
					std::lock_guard<std::mutex> lk(this->m);
					while (futureObj.wait_for(std::chrono::milliseconds(1)) == std::future_status::timeout)
					{
						//to do, do something
						std::this_thread::sleep_for(std::chrono::milliseconds(99));
					}
				}, std::move(futureObj));
			}
		}

		void reset(const std::chrono::seconds& timeous) {

		}
	private:
		std::thread* MThread{ nullptr };
		std::mutex m;
		std::promise<void>* exitSignal{ nullptr };
	};

#endif

	inline std::string GetDirName(const std::string& fullPath) {
		size_t pos = fullPath.rfind("\\");
		if (pos > fullPath.length() - 1) return std::string("");

		return fullPath.substr(0, pos + 1);
	}

	inline std::string GetFileName(const std::string& fullPath) {
		size_t pos = fullPath.rfind("\\");
		size_t pos2 = fullPath.rfind("/");
		if (pos > fullPath.length() - 1 && pos2 > fullPath.length() - 1) return fullPath;

		pos = pos > (fullPath.length() - 1) ? pos2 : (pos2 > (fullPath.length() - 1)) ? pos : pos2 > pos ? pos2 : pos;

		return fullPath.substr(pos + 1, fullPath.length() - pos - 1);
	}

#ifdef _WIN32
	inline bool Exists(const std::string& fullPath, bool isDir = false) {
		DWORD ftype = GetFileAttributes(fullPath.c_str());
		if (INVALID_FILE_ATTRIBUTES == ftype) {
			return false;
		}

		return isDir ? (ftype & FILE_ATTRIBUTE_DIRECTORY) : true;
	}

	inline bool IsNumber(const std::string& s) {
		return !s.empty() &&
			std::find_if(s.begin(), s.end(), [](char c) { return !std::isdigit(c); }) == s.end();
	}

#endif
	inline std::string& Replace(std::string& src, const std::string& ptr, const std::string& replacement) {
		if (ptr.empty()) return src;

		size_t index = 0;
		while (true) {
			index = src.find(ptr, index);
			if (std::string::npos == index) break;

			src.replace(index, ptr.length(), replacement);

			index += replacement.length();
		}

		return src;
	}

	inline int FindStr(const char* src, const char*ptn, size_t lenSrc = 0, size_t sPos = 0) {
		int pos = -1;
		lenSrc = lenSrc == (unsigned int)0 ? strlen(src) : lenSrc;
		size_t lenPtn = strlen(ptn);
        if (lenPtn <= 0 || lenSrc - sPos < lenPtn) {
			return pos;
		}

		for (size_t idx = sPos; idx <= lenSrc - lenPtn; idx++) {
			if (0 == memcmp(src + idx, ptn, lenPtn)) {
				pos = idx;
				break;
			}
		}

		return pos;
	}

	int Trim(const char* src, char* dest, size_t lenDest) {
		if (NULL == src) return -1;
		if (strlen(src) <= 0) return 0;

		bool fullSP = true;
		for (size_t idx = 0; idx < strlen(src); idx++) {
			if (' ' != src[idx]) {
				fullSP = false;
				break;
			}
		}
		if (fullSP) return 0;

		int sIdx = -1;
		int eIdx = -1;
        int idx = 0;

        while (' ' == src[idx] && idx < (int)strlen(src)) {
			sIdx = idx;
			idx++;
		}

        idx = (int)(strlen(src)) - 1;
		while (' ' == src[idx] && idx > -1) {
			eIdx = idx;
			idx--;
		}

		if (-1 == sIdx) sIdx = 0;
		else sIdx += 1;

		if (-1 == eIdx) eIdx = strlen(src) - 1;
		else eIdx -= 1;

        if (eIdx - sIdx + 1 > (int)lenDest) return -1;

		memccpy(dest, src + sIdx, 1, eIdx - sIdx + 1);

		return 0;
	}

	bool StartWith(const char* dest, const char* partn) {
		if (strlen(partn) > strlen(dest)) return false;

		return 0 == memcmp(dest, partn, strlen(partn));
	}

	bool EndWith(const char* dest, const char* partn) {
		if (strlen(partn) > strlen(dest)) return false;

		return 0 == memcmp(dest + (strlen(dest) - strlen(partn)), partn, strlen(partn));
	}

	void ToLowerCase(std::string& str) {
		std::transform(str.begin(), str.end(), str.begin(), [](char in) -> char {
			if (in <= 'Z' && in >= 'A') return in - ('Z' - 'z');

			return in;
		});
	}

	inline void Ltrim(std::string& s) {
		if (s.size() == 0) return;

		int pos = -1;
		for (size_t idx = 0; idx < s.size(); idx++) {
			if (s.at(idx) == ' ') {
				pos = idx;
			}
			else {
				break;
			}
		}
		if (pos != -1) {
			s.erase(0, pos + 1);
		}
	}

	inline void Rtrim(std::string& s) {
		if (s.size() == 0) return;

		int pos = -1;
        for (int idx = (int)s.size() - 1; idx >= 0; idx--) {
			if (s.at(idx) == ' ') {
				pos = idx;
			}
			else {
				break;
			}
		}

		if (pos != -1) {
			s.erase(pos);
		}
	}

	inline void Trim(std::string& s) {
		Ltrim(s);
		Rtrim(s);
	}

	std::list<std::string> Split(const std::string& s, const std::string& c, bool skipEmptyPart = true) {
		std::list<std::string> v;
		std::string::size_type pos1, pos2;
		pos2 = s.find(c);
		pos1 = 0;
		while (std::string::npos != pos2) {
			if (!(pos2 == pos1 && skipEmptyPart))
				v.push_back(s.substr(pos1, pos2 - pos1));

			pos1 = pos2 + c.size();
			pos2 = s.find(c, pos1);
		}

		if (pos1 != s.length()) {
			v.push_back(s.substr(pos1));
		}

		return v;
	}

    int SocketWaitRead(const timeval& iTv, const std::initializer_list<int>& fds) {
		fd_set fdset;
		FD_ZERO(&fdset);
		int maxFD = -1;
		for (const auto& fd : fds) {
			maxFD = maxFD < fd ? fd : maxFD;
			FD_SET(fd, &fdset);
		}

        timeval tv = iTv;
        int fd = select(maxFD + 1, &fdset, NULL, NULL, &tv);

        for (const auto& fd: fds) {
            if (FD_ISSET(fd, &fdset)) {
                return fd;
            }
        }

        return fd;
	}

    int SocketWaitWrite(const timeval& iTv, const std::initializer_list<int>& fds) {
		fd_set fdset;
		FD_ZERO(&fdset);
		int maxFD = -1;
		for (const auto& fd : fds) {
			maxFD = maxFD < fd ? fd : maxFD;
			FD_SET(fd, &fdset);
		}

        timeval tv = iTv;
        int fd = select(maxFD + 1, NULL, &fdset, NULL, &tv);

        for (const auto& fd: fds) {
            if (FD_ISSET(fd, &fdset)) {
                return fd;
            }
        }

        return fd;
	}


#ifdef _WIN32
#include <windows.h>

	std::string GbkToUtf8(const char *src_str)
	{
		int len = MultiByteToWideChar(CP_ACP, 0, src_str, -1, NULL, 0);
		wchar_t* wstr = new wchar_t[len + 1];
		memset(wstr, 0, len + 1);
		MultiByteToWideChar(CP_ACP, 0, src_str, -1, wstr, len);
		len = WideCharToMultiByte(CP_UTF8, 0, wstr, -1, NULL, 0, NULL, NULL);
		char* str = new char[len + 1];
		memset(str, 0, len + 1);
		WideCharToMultiByte(CP_UTF8, 0, wstr, -1, str, len, NULL, NULL);
		std::string strTemp = str;
		if (wstr) delete[] wstr;
		if (str) delete[] str;
		return strTemp;
	}

	std::string Utf8ToGbk(const char *src_str)
	{
		int len = MultiByteToWideChar(CP_UTF8, 0, src_str, -1, NULL, 0);
		wchar_t* wszGBK = new wchar_t[len + 1];
		memset(wszGBK, 0, len * 2 + 2);
		MultiByteToWideChar(CP_UTF8, 0, src_str, -1, wszGBK, len);
		len = WideCharToMultiByte(CP_ACP, 0, wszGBK, -1, NULL, 0, NULL, NULL);
		char* szGBK = new char[len + 1];
		memset(szGBK, 0, len + 1);
		WideCharToMultiByte(CP_ACP, 0, wszGBK, -1, szGBK, len, NULL, NULL);
		std::string strTemp(szGBK);
		if (wszGBK) delete[] wszGBK;
		if (szGBK) delete[] szGBK;
		return strTemp;
	}
#else
#include <iconv.h>

	int GbkToUtf8(char *str_str, size_t src_len, char *dst_str, size_t dst_len)
	{
		iconv_t cd;
		char **pin = &str_str;
		char **pout = &dst_str;

		cd = iconv_open("utf8", "gbk");
		if (cd == 0)
			return -1;
		memset(dst_str, 0, dst_len);
        if (iconv(cd, pin, &src_len, pout, &dst_len) > 0)
			return -1;
		iconv_close(cd);
		*pout = '\0';

		return 0;
	}

	int Utf8ToGbk(char *src_str, size_t src_len, char *dst_str, size_t dst_len)
	{
		iconv_t cd;
		char **pin = &src_str;
		char **pout = &dst_str;

		cd = iconv_open("gbk", "utf8");
		if (cd == 0)
			return -1;
		memset(dst_str, 0, dst_len);
        if (iconv(cd, pin, &src_len, pout, &dst_len) > 0)
			return -1;
		iconv_close(cd);
		*pout = '\0';

		return 0;
	}
#endif

}
#endif //TOOLS_H
