#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <auparse.h>
#include <iostream>
#include <fstream>
#include <ctime>
#include <nlohmann/json.hpp>

using namespace std;
using json = nlohmann::json;


// inline int FromHex(unsigned int c) 
// {
// 	return ((c >= '0') && (c <= '9')) ? int(c - '0') :
// 		((c >= 'A') && (c <= 'F')) ? int(c - 'A' + 10) :
// 		((c >= 'a') && (c <= 'f')) ? int(c - 'a' + 10) :
// 		/* otherwise */              -1;
// }


// std::string HexDecode(const std::string& hex)
// {
// 	std::string res;
// 	res.resize(hex.size() + 1 / 2);
// 	unsigned char* pResult = (unsigned char*)res.data() + res.size();
// 	bool odd_digit = true;
 
// 	for(int i = hex.size() - 1; i >= 0; i--)
// 	{
// 		unsigned char ch = (unsigned char)(hex.at(i));
// 		int tmp = FromHex(ch);
// 		if (tmp == -1)
// 			continue;
// 		if (odd_digit) {
// 			--pResult;
// 			*pResult = tmp;
// 			odd_digit = false;
// 		} else {
//                         if(tmp == 0)
//                         {
//                             *pResult = 32;
//                             odd_digit = true;
//                             continue;
//                         }
// 			    *pResult |= tmp << 4;
// 			    odd_digit = true;
                        
// 		}
// 	}

// 	res.erase(0, pResult - (unsigned char*)res.data());
        
// 	return res;
// }



int main(int argc, char *argv[])
{
        //初始化数据源
        auparse_state_t *au = auparse_init(AUSOURCE_DESCRIPTOR, 0);
        if (au == NULL) {
                printf("Error initializing event source\n");
                return 1;
        }


   
        string encode,postData,empty("");
        char timeBuffer[80] = {0};
        

        char *server_addr = argv[1];

        json js;
        
        while (auparse_next_event(au) > 0) {
                // Event level
                const char *item, *evkind, *action, *str, *how, *field;
                time_t evtime;
                
                //判断是否为event结束
                if(!strcmp(auparse_get_type_name(au),"EOE")){
                        continue;
                }
                
                //日志文件
                ofstream file("/var/log/honeylog");
                // Do normalization
                if (auparse_normalize(au, NORM_OPT_NO_ATTRS) == 1) {
                        printf("error normalizing - skipping\n");
                        continue;
                }

                // Event time
                evtime = auparse_get_time(au);
                if( evtime == 0){
                        printf("get timestamp error\n");
                }else{
                        struct tm* timeinfo = localtime(&evtime);
                        strftime(timeBuffer,sizeof(timeBuffer) ,"%Y-%m-%d %H:%M:%S", timeinfo);
                }
                js["Time"] = string(timeBuffer);


                js["Subject"] = empty;
                if (auparse_normalize_subject_secondary(au) == 1) {
                        const char *subj = auparse_interpret_field(au);
                        field = auparse_get_field_name(au);
                        js["Subject"] = subj;
                }
                
                //Key
                js["Key"] = empty;
                if (auparse_normalize_key(au) == 1) {
                        const char *key = auparse_interpret_field(au);
                        js["Key"] = key;
                }else{
                        js.clear();
                        continue;

                }

                // Action
                js["Action"] = empty;
                action = auparse_normalize_get_action(au);
                if (action) {
                        js["Action"] = string(action);
                }
                

                // How action was performed
                js["How"] = empty;
                how = auparse_normalize_how(au);
                if (how){
                        js["How"] = how;
                }
                

                // Show file path
                js["FilePath"] = empty;
                evkind = auparse_normalize_get_event_kind(au);
                if(!strcmp(evkind,"audit-rule")){
                        auparse_next_record(au);
                        char *file_path = (char*)auparse_find_field(au,"name");
                        if(file_path != NULL){js["FilePath"] = string(file_path).substr(1,strlen(file_path)-2);}
                        
                        
                }

                //Show bash command
                js["Bash"] = empty;
                if(!strcmp(evkind,"audit-rule")){
                        auparse_next_record(au);
                        char *proctitle = (char*)auparse_find_field(au,"proctitle");
                        cout<<static_cast<const void *>(proctitle)<<endl;
                        if(proctitle != NULL && proctitle[0] != 34)
                        {
                                string cmd = HexDecode(string((const char *)proctitle));
                                js["Bash"] = cmd;
                        }else if (proctitle != NULL)
                        {
                                js["Bash"] = proctitle;

                        }
                        
                }                

                

                cout<<js.dump()<<endl;
                string log_detail = js.dump();
                file << log_detail;
                file.close();
                encode.clear();
                js.clear();
                
        }
        
       
        printf("---\n");
        auparse_destroy(au);
        return 0;
}