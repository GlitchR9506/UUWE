//
// UUWE VERSION
//
#define DVER "22.10.18.00"	// First:[22.10.15.00]
#define RVER "PREALPHA 1"

void __cdecl LogMsgNaked(const char* format, ...);

//
// Defines 
// 
#define IMPLEMENT_FUNCTION printf("\t[%s:%s] Called\r\n", __MODULE__, __FUNCTION__);
#define STRING(str) #str 

#if !defined(__PRETTY_FUNCTION__) && !defined(__GNUC__)
#define __PRETTY_FUNCTION__ __FUNCSIG__
#endif

#define GETFUNC() ""
#define GETLINE() STRING(__LINE__)

#define COMMA ,
#define LogMsgEx(code, format, ...)  \
    SYSTEMTIME st, lt, dt; \
	GetSystemTime(&st); \
	GetLocalTime(&lt);  \
	dt = et;\
	dt = st - et;\
	LogMsgNaked("[%s][%s:"GETFUNC()"{line:%i}] \r\n  @ LOCAL[%02d:%02d:%02d] : UTC[%02d:%02d:%02d] : ELAPSED[%02d:%02d:%02d]\r\n\r\n\t"format,#code,__MODULE__,__LINE__,  lt.wHour, lt.wMinute, lt.wSecond, st.wHour, st.wMinute, st.wSecond, dt.wHour, dt.wMinute, dt.wSecond, __VA_ARGS__); \
	printf("[%s][%s:"GETFUNC()"{line:%i}] \r\n  @ LOCAL[%02d:%02d:%02d] : UTC[%02d:%02d:%02d] : ELAPSED[%02d:%02d:%02d]\r\n\r\n\t"format,#code,__MODULE__,__LINE__,  lt.wHour, lt.wMinute, lt.wSecond, st.wHour, st.wMinute, st.wSecond, dt.wHour, dt.wMinute, dt.wSecond, __VA_ARGS__)

//
// shu' yer fuckin aiss
//
#ifdef __INTELLISENSE__
#  undef LogMsgEx
#  define LogMsgEx(...)
#endif

void __cdecl LogMsgNaked(const char* format, ...)
{
	char    buf[4096], * p = buf;
	va_list args;
	int     n;

	va_start(args, format);
	n = _vsnprintf(p, sizeof buf - 3, format, args); // buf-3 is room for CR/LF/NUL
	va_end(args);

	p += (n < 0) ? sizeof buf - 3 : n;

	while (p > buf && isspace(p[-1]))
		*--p = '\0';

	//*p++ = '\r';
	//*p++ = '\n';
	*p = '\0';

	OutputDebugStringA(buf);
}