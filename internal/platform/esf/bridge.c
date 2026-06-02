// SPDX-License-Identifier: MIT
/* Copyright (c) 2026 warmor */

// C bridge for Endpoint Security Framework
// This file provides the C callback bridge between ESF and Go

#include <EndpointSecurity/EndpointSecurity.h>
#include <stdlib.h>
#include <stdio.h>
#include "_cgo_export.h"

// Global client pointer for callback
static es_client_t *global_client = NULL;

// Event handler callback that bridges to Go
static void event_handler(es_client_t *client, const es_message_t *message) {
    if (message == NULL) {
        return;
    }
    
    // Call Go function
    // Note: We need to pass a non-const pointer to Go
    goEventHandler((es_message_t *)message);
}

// Create ESF client with Go callback
es_new_client_result_t create_esf_client(es_client_t **client) {
    es_new_client_result_t result = es_new_client(client, ^(es_client_t *c, const es_message_t *message) {
        event_handler(c, message);
    });
    
    if (result == ES_NEW_CLIENT_RESULT_SUCCESS) {
        global_client = *client;
    }
    
    return result;
}

// Delete ESF client
es_return_t delete_esf_client(es_client_t *client) {
    if (client != NULL) {
        es_delete_client(client);
        global_client = NULL;
    }
    return ES_RETURN_SUCCESS;
}

// Subscribe to events
es_return_t subscribe_events(es_client_t *client, es_event_type_t *events, uint32_t count) {
    if (client == NULL || events == NULL || count == 0) {
        return ES_RETURN_ERROR;
    }
    
    return es_subscribe(client, events, count);
}

// Unsubscribe from events
es_return_t unsubscribe_events(es_client_t *client, es_event_type_t *events, uint32_t count) {
    if (client == NULL || events == NULL || count == 0) {
        return ES_RETURN_ERROR;
    }
    
    return es_unsubscribe(client, events, count);
}

// Respond to AUTH event
es_respond_result_t respond_auth(es_client_t *client, const es_message_t *message, es_auth_result_t result, bool cache) {
    if (client == NULL || message == NULL) {
        return ES_RESPOND_RESULT_ERR_INVALID_ARGUMENT;
    }
    
    return es_respond_auth_result(client, message, result, cache);
}

// Helper: Get process executable path
const char* get_process_path(const es_process_t *process) {
    if (process == NULL || process->executable == NULL || process->executable->path.data == NULL) {
        return NULL;
    }
    return process->executable->path.data;
}

// Helper: Get file path from open event
const char* get_open_file_path(const es_event_open_t *event) {
    if (event == NULL || event->file == NULL || event->file->path.data == NULL) {
        return NULL;
    }
    return event->file->path.data;
}

// Helper: Get file path from create event
const char* get_create_file_path(const es_event_create_t *event) {
    if (event == NULL || event->destination.new_path.dir == NULL) {
        return NULL;
    }
    // TODO: Construct full path from dir + filename
    return NULL;
}

// Helper: Get PID from audit token
pid_t get_pid_from_token(audit_token_t token) {
    return audit_token_to_pid(token);
}

// Helper: Get UID from audit token
uid_t get_uid_from_token(audit_token_t token) {
    return audit_token_to_euid(token);
}

// Helper: Get GID from audit token
gid_t get_gid_from_token(audit_token_t token) {
    return audit_token_to_egid(token);
}


