#ifndef __TRACEPOINT_DEFS_H
#define __TRACEPOINT_DEFS_H

struct trace_event_raw_sys_enter {
	unsigned long long unused;
	long id;
	unsigned long args[6];
};

struct trace_event_raw_sys_exit {
	unsigned long long unused;
	long id;
	long ret;
};

#endif /* __TRACEPOINT_DEFS_H */
