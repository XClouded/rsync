
#include <stdio.h>
#include <stdint.h>
#include <strings.h>
#include <string.h>

#include <zlib.h>
#include <openssl/md5.h>

#include <vector>
#include <map>
#include <fstream>
#include <string>

struct CheckSumInfo
{
	CheckSumInfo()
	{
		id = 0; 
		weak_sum = 0; 
		bzero(strong_sum, sizeof(strong_sum)); 
	}

	uint32_t id; 
	uint32_t len; 
	uint32_t weak_sum;		//	adler32
	char	strong_sum[16]; //md5
}; 

const int block_sz = 64; 

std::vector<CheckSumInfo> load_dest_info(const char* f)
{
	std::vector<CheckSumInfo> vec; 

	std::ifstream _if; 
	_if.open(f, std::ifstream::binary);

	_if.seekg(0, _if.end); 
	int len = _if.tellg(); 
	_if.seekg(0, _if.beg); 

	int cur = 0; 
	char buff[block_sz] = {0}; 
	int id = 0; 

	while (len > 0)
	{
		int read = len >= block_sz ? block_sz : len; 
		_if.read(buff, read); 

		//calc checksum
		CheckSumInfo sum; 
		sum.id = id; 
		sum.len = read; 
		sum.weak_sum = ::adler32(0, (const Bytef*)buff, read); 
		::MD5((const unsigned char*)buff, read, (unsigned char*)sum.strong_sum); 

		vec.push_back(sum); 

		printf("id:%d len:%d weak_sum:%u\n", id, read, sum.weak_sum); 

		++id; 
		len -= read; 
	}

	_if.close(); 

	return vec; 
}

uint32_t rolling_checkSum(uint32_t sum, char s, char e, uint32_t len)
{
	uint32_t a = sum & 0xFFFF; 
	uint32_t b = sum >> 16; 

	uint32_t a1 = (a - s + e) & 0xFFFF; 
	uint32_t b1 = (b - len * s + a1) & 0xFFFF; 

	return a1 + (b1 << 16); 
}

struct TransformInfo
{
	TransformInfo()
	{
		type = len = 0; 
	}

	uint8_t type;	//0-add 1-file_dest already have
	uint32_t len;	//0-len 1-id; 
	std::vector<char> data; 
}; 

void src_file_check(const char* f, const std::vector<CheckSumInfo>& info)
{
	std::map<uint32_t, std::vector<CheckSumInfo> > data; 
	for (size_t i = 0; i != info.size(); ++i)
	{
		data[info[i].weak_sum].push_back(info[i]); 
	}

	std::ifstream _if; 
	_if.open(f, std::ifstream::binary);

	_if.seekg(0, _if.end); 
	int len = _if.tellg(); 
	_if.seekg(0, _if.beg); 

	printf("src_file len:%d\n", len); 

	std::vector<char> file_data(len); 
	_if.read(&file_data[0], len); 
	_if.close(); 

	std::vector<TransformInfo> vec; 
	std::vector<char> need_send; 

	int cur_idx = 0; 
	bool rolling = false; 
	uint32_t last_sum = 0; 

	while (cur_idx < len)
	{
		uint32_t sum = 0; 
		int test_len = 0; 
		if (rolling && cur_idx + block_sz < len)
		{
			sum = rolling_checkSum(last_sum, file_data[cur_idx - 1], file_data[cur_idx + block_sz - 1], block_sz); 
			test_len = block_sz; 
		}
		else
		{
			int left = len - cur_idx; 
			test_len = (left >= block_sz) ? block_sz : left; 
			sum = ::adler32(0, (const Bytef*)(&file_data[cur_idx]), test_len); 
		}

		last_sum = sum; 

		bool find = false; 
		//check weak_sum
		std::map<uint32_t, std::vector<CheckSumInfo> >::iterator it = data.find(sum); 
		if (it != data.end())
		{
			//check strong_sum
			unsigned char md[16] = {0}; 
			::MD5((const unsigned char*)(&file_data[cur_idx]), test_len, md); 

			for (size_t i = 0; i != it->second.size(); ++i)
			{
				if (memcmp(md, it->second[i].strong_sum, sizeof(md)) == 0)
				{
					if (!need_send.empty())
					{
						TransformInfo add; 
						add.type = 0; 
						add.len = need_send.size(); 
						add.data = need_send; 
						vec.push_back(add); 

						need_send.clear(); 
					}

					TransformInfo z; 
					z.type = 1; 
					z.len = it->second[i].id; 
					vec.push_back(z); 

					find = true; 
					rolling = false; 
					cur_idx += test_len; 
					break; 
				}
			}
		}

		if (!find)
		{
			need_send.push_back(file_data[cur_idx]); 

			rolling = true; 
			++cur_idx; 
		}
	}

	int total_len = 0; 
	for (size_t i = 0; i != vec.size(); ++i)
	{
		total_len += 5; 
		if (vec[i].type == 1)
		{
			printf("send:%d type:%d id:%d\n", i, vec[i].type, vec[i].len); 
		}
		else
		{
			total_len += vec[i].data.size(); 
			std::string w(vec[i].data.begin(), vec[i].data.end()); 
			printf("send:%d type:%d\ndata:%s\nlen:%d\n", i, vec[i].type, w.c_str(), w.size()); 
		}
	}
	printf("total_len:%d percent:%.2f\n", total_len, total_len*1.0f/len); 
}

int main(int argc, char* argv[])
{
	if (argc != 3)
	{
		printf("usage: this srcfile destfile"); 
	}

	std::vector<CheckSumInfo> vec = load_dest_info(argv[2]); 

	src_file_check(argv[1], vec); 

/*
	char buff[] = "1uiddkajeuiaoajdljgjaljdaleuqohghgla"; 
	uint32_t num_1 = ::adler32(0, (const Bytef*)buff, 8); 
	uint32_t num_2 = ::adler32(0, (const Bytef*)(buff + 1), 8); 
	uint32_t num_3 = rolling_checkSum(num_1, buff[0], buff[8], 8); 
*/
	return 0; 
}
