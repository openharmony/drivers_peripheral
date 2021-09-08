extern "C" {
void acm_open();
void acm_close();
void acm_write(char * data);
void acm_read(char *str, int timeout = 5);
void acm_prop_regist(const char *propName, const char *propValue);
void acm_prop_write(const char *propName, const char *propValue);
void acm_prop_read(const char *propName, char *propValue);
}
