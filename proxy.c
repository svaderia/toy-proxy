#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <event2/event.h>
#include <event2/listener.h>
#include <event2/bufferevent.h>
#include <event2/buffer.h>
#include <arpa/inet.h>
#include <ctype.h>
#include <stdbool.h>
#include <assert.h>

#include "queue.h"

/** Hardcoded configurations **/
static const char *LISTEN_ADDR = "0.0.0.0";
static const int LISTEN_PORT = 5433; // Proxy port

// Hardcoded authentication (username only for simplicity)
// static const char *PROXY_USER = "admin";

// Backend servers (hardcoded)
// #define BACKEND_COUNT 2
// static const char *BACKENDS[BACKEND_COUNT] = {
//     "127.0.0.1", // first backend
//     "127.0.0.1"  // second backend
// };
// static const int BACKEND_PORTS[BACKEND_COUNT] = { 5432, 5432 };

// TODO figure out increased backend once we have the protocol working

#define BACKEND_COUNT 1
static const char *BACKENDS[BACKEND_COUNT] = {
    "127.0.0.1", // first backend
};
static const int BACKEND_PORTS[BACKEND_COUNT] = { 5432 };


// TODO I don't know if these are used
// PostgreSQL protocol message types (a small subset)
#define MSG_STARTUP 0
#define MSG_QUERY 'Q'
#define MSG_READY_FOR_QUERY 'Z'
#define MSG_AUTHENTICATION 'R'
#define MSG_ROW_DESCRIPTION 'T'
#define MSG_DATA_ROW 'D'
#define MSG_COMMAND_COMPLETE 'C'
#define MSG_ERROR_RESPONSE 'E'

// AuthenticationOk code
#define AUTH_OK 0

// ReadyForQuery transaction status
#define STATUS_IDLE 'I'
#define STATUS_INTRANS 'T'
#define STATUS_INERROR 'E'


// When a client connects to postgres, they exchange a sequence of messages that
//  look something like this:

// client sends "startup message"
// server sends "authentication message" 'R'
// client sends "password message" 'p' (with hashing scheme)
// server sends "authentication message" 'R' (again?)
//  - side note, this is probably part of the authentication protocol. 
//     Exchanging salts or something
// client sends 'p'
// server sends 'R', 'R'
// server sends many 'S' - sending server settings (Parameter Status Message)
// server sends 'K' - key for query cancellation
// server sends 'Z' - ready for query

// The following fields are my attempt to plainly copy these messages in the 
//  hopes that every client authenticates the same way. This code is awful, but
//  I'd rather have something working than spend time perfectly parsing every
//  setting

struct startup_msg {
    unsigned char *msg;
    size_t len;
};

enum client_startup_step {
    STARTUP_CLIENT, R, COMPLETE_CLIENT
};

enum server_startup_step {
    STARTUP_SERVER, P, COMPLETE_SERVER
};

// Shitty queue
struct message_list_node {
    struct startup_msg msg;
    struct message_list_node *next;
};

static void message_list_node_init(struct message_list_node *node, void *msg, size_t len) {

    node->msg.msg = msg;
    node->msg.len = len;
    node->next = NULL;
}

struct message_list {
    struct message_list_node *head;
    struct message_list_node *tail;
};

// static void message_list_init(struct message_list *list) {
//     list->head = NULL;
//     list->tail = NULL;
// }

// append-only
static void message_list_insert(struct message_list *list, 
        struct message_list_node *node) {
    
    if (list->head == NULL) {
        list->head = node;
    } else {
        list->tail->next = node;
    }
    list->tail = node;
}

// Fill these in the first time the user authenticates. Note that this may be 
//  prone to races if there isn't only one thread at first.

// startup msg
struct startup_msg client_startup_message;
// first 'R' message
struct startup_msg server_auth_msg_1;
// first 'p' message
struct startup_msg client_pw_msg_2;
// everything else until and including 'ready for query'
struct message_list server_parameter_list = {NULL, NULL};

// I don't think we need server because no threads will be alive to initialize a
//  second server lol
int startup_client_id = 0;


// TODO each server connection should store if it is initialized. If it is not,
//  its first client organically does the protocol. This is awful but will allow
//  us to get benchbase working probably.
// TODO is this wrong? possibly racey...
// TODO if server is uninitialized, and startup protocol exists, do it when a 
//  client tries to connect and it is uninitialized

enum global_startup_step {
    UNINITIALIZED_STARTUP_GLOBAL, IN_PROGRESS_STARTUP_GLOBAL, COMPLETE_STARTUP_GLOBAL
};

enum global_startup_step global_startup_status = UNINITIALIZED_STARTUP_GLOBAL;

// I am ashamed to ever written this
struct q_list waiting_client_queue = {NULL, NULL};
// so many blobbies
struct waiting_client {
    struct bufferevent *bev;
    void *arg;
};


struct client_conn; // forward declaration

struct server_conn {
    struct bufferevent *bev;
    bool in_use; // 0 if free, 1 if assigned
    int index;  // which backend index
    struct client_conn *current_client;
    enum server_startup_step init_status;
};

struct client_conn {
    struct bufferevent *bev;
    struct server_conn *assigned_server;
    enum client_startup_step init_status;
    int id;
};

int client_id_counter = 0;

static struct event_base *base;
static struct server_conn servers[BACKEND_COUNT];

static void log_info(const char *msg) {
    fprintf(stdout, "[INFO] %s\n", msg);
}

static void log_hex_data(const unsigned char *data, size_t len) {
    fprintf(stdout, "[DEBUG] Data (hex): ");
    for (size_t i = 0; i < len; i++) {
        fprintf(stdout, "%02X ", data[i]);
    }
    fprintf(stdout, "\n");
}

static void log_text_data(const char *label, const char *data, size_t len) {
    // Safely print up to len characters (not necessarily null-terminated)
    fprintf(stdout, "[DEBUG] %s (text, length=%zu): ", label, len);
    for (size_t i = 0; i < len; i++) {
        unsigned char c = (unsigned char)data[i];
        // Print printable ASCII only, replace others with '.'
        if (c >= 32 && c < 127) {
            fputc(c, stdout);
        } else {
            fputc('.', stdout);
        }
    }
    fputc('\n', stdout);
}

static struct server_conn* get_free_server(void) {
    for (int i=0; i<BACKEND_COUNT; i++) {
        if (!servers[i].in_use) {
            return &servers[i];
        }
    }
    return NULL;
}

static void release_server(struct server_conn *srv) {
    if (srv) {
        srv->in_use = false;
        srv->current_client = NULL;
    }
}

static void bufferevent_wrote(struct bufferevent *bev, const void *msg, size_t len) {
    printf("BUFFEREVENT WRITE!!\n");
    log_hex_data(msg, len);
    log_text_data("", msg, len);
    printf("END BUFFEREVENT WRITE\n");
    bufferevent_write(bev, msg, len);
}

// /** Send a simple AuthenticationOk and ReadyForQuery message to the client **/
// static void send_auth_ok(struct client_conn *client) {
//     // AuthenticationOk: 'R' int32 len=8 int32=0
//     char auth_ok_msg[9];
//     auth_ok_msg[0] = MSG_AUTHENTICATION;
//     *(int32_t*)(auth_ok_msg+1) = htonl(8);
//     *(int32_t*)(auth_ok_msg+5) = htonl(AUTH_OK);

//     bufferevent_wrote(client->bev, auth_ok_msg, 9);

//     // ReadyForQuery: 'Z' int32=5 status='I'
//     char ready_msg[6];
//     ready_msg[0] = MSG_READY_FOR_QUERY;
//     *(int32_t*)(ready_msg+1) = htonl(5);
//     ready_msg[5] = STATUS_IDLE;

//     bufferevent_wrote(client->bev, ready_msg, 6);
// }

/** Send ErrorResponse (very minimal) **/
static void send_error_response(struct client_conn *client, const char *msg) {
    size_t msg_len = strlen(msg);
    // 'E' + length(4) + 'M' + msg + '\0' + '\0'
    size_t pkt_len = 1 + 4 + 1 + msg_len + 1 + 1;
    char *err_buf = malloc(pkt_len);
    err_buf[0] = MSG_ERROR_RESPONSE;
    *(int32_t*)(err_buf+1) = htonl((int32_t)pkt_len);
    err_buf[5] = 'M';
    memcpy(err_buf+6, msg, msg_len);
    err_buf[6+msg_len] = '\0';
    err_buf[6+msg_len+1] = '\0';

    bufferevent_wrote(client->bev, err_buf, pkt_len);
    free(err_buf);
}


/** Connect to a backend server if needed
    For this PoC we assume they're connected at init time. **/
// static int connect_backend(struct server_conn *srv) {
//     return 1; // assume already connected for PoC
// }

/** Send a simple query to the backend **/
static void send_query_to_backend(struct server_conn *srv, const char *query) {
    size_t qlen = strlen(query);
    int32_t msg_len = (int32_t)(4 + qlen + 1);
    char *buf = malloc(1 + msg_len);
    buf[0] = MSG_QUERY;
    *(int32_t*)(buf+1) = htonl(msg_len);
    memcpy(buf+5, query, qlen);
    buf[5+qlen] = '\0';

    bufferevent_wrote(srv->bev, buf, 1+msg_len);
    free(buf);
}


// TODO probably not necessrary for simple queries, luckily we have the 
//  setting...
/** Helper: case-insensitive starts with a keyword **/
// static int starts_with_keyword(const char *query, const char *keyword) {
//     size_t klen = strlen(keyword);
//     while (isspace((unsigned char)*query)) query++;
//     return strncasecmp(query, keyword, klen) == 0;
// }




// static void send_ssl_denied(struct client_conn *client) {
//     // Send 'N' to indicate no SSL
//     char n = 'N';
//     bufferevent_wrote(client->bev, &n, 1);
// }

// static void send_parameter_status(struct client_conn *client, const char *key, const char *value) {
//     // ParameterStatus: 'S' + length + key/value + '\0' + '\0'
//     // length = 4 + strlen(key)+1 + strlen(value)+1
//     size_t klen = strlen(key);
//     size_t vlen = strlen(value);
//     int32_t msg_len = 4 + (int32_t)(klen+1+vlen+1);
//     char *buf = malloc(1 + msg_len);
//     buf[0] = 'S';
//     *(int32_t*)(buf+1) = htonl(msg_len);
//     memcpy(buf+5, key, klen);
//     buf[5+klen] = '\0';
//     memcpy(buf+5+klen+1, value, vlen);
//     buf[5+klen+1+vlen] = '\0';

//     bufferevent_wrote(client->bev, buf, 1 + msg_len);
//     free(buf);
// }

// static void send_backend_key_data(struct client_conn *client, int32_t pid, int32_t key) {
//     // BackendKeyData: 'K' int32 len=12 int32 pid int32 key
//     char buf[1+4+4+4];
//     buf[0] = 'K';
//     *(int32_t*)(buf+1) = htonl(12);
//     *(int32_t*)(buf+5) = htonl(pid);
//     *(int32_t*)(buf+9) = htonl(key);
//     bufferevent_wrote(client->bev, buf, 13);
// }

// static void send_ready_for_query(struct client_conn *client, char status) {
//     // ReadyForQuery: 'Z' int32=5 status(1)
//     char ready_msg[6];
//     ready_msg[0] = 'Z';
//     *(int32_t*)(ready_msg+1) = htonl(5);
//     ready_msg[5] = status;
//     bufferevent_wrote(client->bev, ready_msg, 6);
// }

// /** Updated send_auth_ok to send parameter status & backend key data afterwards */
// static void complete_startup_sequence(struct client_conn *client) {
//     // AuthenticationOk
//     {
//         char auth_ok_msg[9];
//         auth_ok_msg[0] = 'R';
//         *(int32_t*)(auth_ok_msg+1) = htonl(8);
//         *(int32_t*)(auth_ok_msg+5) = htonl(0);
//         bufferevent_wrote(client->bev, auth_ok_msg, 9);
//     }

//     // Send some ParameterStatus messages
//     send_parameter_status(client, "server_version", "13.3");
//     send_parameter_status(client, "client_encoding", "UTF8");
//     send_parameter_status(client, "DateStyle", "ISO, MDY");
//     send_parameter_status(client, "integer_datetimes", "on");
//     send_parameter_status(client, "standard_conforming_strings", "on");

//     // BackendKeyData
//     send_backend_key_data(client, 1234, 5678); // arbitrary pid and key

//     // Finally ReadyForQuery
//     send_ready_for_query(client, 'I');
// }


static void log_debug(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    fprintf(stdout, "[DEBUG] ");
    vfprintf(stdout, fmt, ap);
    fprintf(stdout, "\n");
    va_end(ap);
}

static void alloc_startup_server(struct client_conn **client, struct evbuffer *input) {
    struct server_conn *srv = (*client)->assigned_server;
    if (!srv) {
        srv = get_free_server();
        if (!srv) {
            // No free backend connection
            send_error_response(*client, "No free backend connection available");
            // evbuffer_drain(input, packet_len);
            // return -1;
            exit(-1);
        }
        srv->in_use = true;
        srv->current_client = *client;
        (*client)->assigned_server = srv;
    }
}

// static int handle_startup_message(struct client_conn *client, struct evbuffer *input) {
//     size_t len = evbuffer_get_length(input);
//     if (len < 8) {
//         // Not enough data for even the length+protocol
//         return 0;
//     }

//     unsigned char *data = evbuffer_pullup(input, len);
//     int32_t packet_len = ntohl(*(int32_t*)data);
//     if ((int)len < packet_len) {
//         // Not a full packet yet
//         return 0;
//     }

//     int32_t protocol = ntohl(*(int32_t*)(data+4));

//     if (protocol == 80877103) {
//         log_debug("SSL Request????\n");
//         log_debug("We really probably don't want to have to deal with this for now");

//         // SSLRequest
//         evbuffer_drain(input, packet_len);
//         char n = 'N'; // No SSL
//         bufferevent_wrote(client->bev, &n, 1);
//         return 0; // Expect another startup message from the client
//     }

//     // It's a normal StartupMessage. We'll forward it directly to the backend.
//     // Assign a backend if not already assigned.
//     struct server_conn *srv = client->assigned_server;
//     if (!srv) {
//         srv = get_free_server();
//         if (!srv) {
//             // No free backend connection
//             send_error_response(client, "No free backend connection available");
//             evbuffer_drain(input, packet_len);
//             return -1;
//         }
//         srv->in_use = true;
//         srv->current_client = client;
//         client->assigned_server = srv;
//     }

//     // Forward the entire startup packet to the backend
//     bufferevent_wrote(srv->bev, data, packet_len);

//     // Drain the startup message from the client's buffer
//     evbuffer_drain(input, packet_len);

//     // We have now forwarded the startup message to the backend.
//     // The backend will send AuthenticationOk/ParameterStatus/etc.
//     // Set awaiting_startup = 0 so we no longer treat incoming client data as startup.
//     // client->awaiting_startup = 0;

//     // We do not send anything to the client now. The backend will do the authentication dance.
//     // We will forward backend messages (R, S, K, Z, E) to the client until we get ReadyForQuery.

//     return 1;
// }


static void handle_client_query(struct client_conn *client, struct evbuffer *input) {
    size_t len = evbuffer_get_length(input);
    if (len < 5) {
        return; // not enough data
    }

    unsigned char *data = evbuffer_pullup(input, len);
    int32_t msg_len = ntohl(*(int32_t*)(data+1));
    if (len < (size_t)(msg_len+1)) {
        return; // not complete
    }

    const char *query = (const char*)(data+5);

    struct server_conn *srv = client->assigned_server;

    if (!srv) {
        // If no server assigned yet (should not happen now since we assigned at startup)
        srv = get_free_server();
        if (!srv) {
            send_error_response(client, "No free backend connection");
            return;
        }
        srv->in_use = true;
        srv->current_client = client;
        client->assigned_server = srv;
    }

    // Check if backend handshake done
    if (srv->init_status != COMPLETE_SERVER) {
        log_debug("Query received before backend handshake completed");
        send_error_response(client, "Backend not ready (handshake not completed)");
        return;
    }

    send_query_to_backend(srv, query);
    evbuffer_drain(input, msg_len+1);
}


// The first global initilization, must set global values and give them back to
//  the server
// @pre there is a valid message in the queue
static void first_initialize_client_conn(struct server_conn *srv, struct client_conn *client) {
    struct evbuffer *input = bufferevent_get_input(client->bev);
    size_t input_len = evbuffer_get_length(input);

    unsigned char *data = evbuffer_pullup(input, 5);
    char msg_type = data[0];
    int32_t msg_len = ntohl(*(int32_t*)(data+1));
    int32_t msg_buflen = msg_len + 1;
    if (msg_type == 0) {
        msg_len = ntohl(*(int32_t*)(data));
        msg_buflen = msg_len;
    }

    if (input_len < msg_len ||  msg_len < 4) {
        log_info("Not enough values in buffer to generate request");
        assert(false);
    }

    unsigned char *msgcpy = malloc(msg_buflen);
    memcpy(msgcpy, data, msg_buflen);
    // Could do assertions, idrc

    switch (client->init_status) {
        case STARTUP_CLIENT:
            client_startup_message.msg = msgcpy;
            client_startup_message.len = msg_buflen;
            client->init_status = R;
            global_startup_status = IN_PROGRESS_STARTUP_GLOBAL;
            break;
        case R:
            client_pw_msg_2.msg = msgcpy;
            client_pw_msg_2.len = msg_buflen;
            // Hopefully client does not spam before getting ack
            client->init_status = COMPLETE_CLIENT;
            break;
        default:
            log_info("initialize client (first) called on initialized client");
            exit(-1);
            break;
    }
    bufferevent_wrote(srv->bev, msgcpy, msg_buflen);
    evbuffer_drain(input, msg_buflen);
}


// The first global initilization, must set global values and give them back to
//  the server
// @pre there is a valid message in the queue
static void initialize_client_conn(struct server_conn *srv, struct client_conn *client) {
    struct evbuffer *input = bufferevent_get_input(client->bev);
    size_t input_len = evbuffer_get_length(input);

    unsigned char *data = evbuffer_pullup(input, 5);
    // Could do assertions, idrc
    char msg_type = data[0];
    int32_t msg_len = ntohl(*(int32_t*)(data+1));
    int32_t msg_buflen = msg_len + 1;
    if (msg_type == 0) {
        msg_len = ntohl(*(int32_t*)(data));
        msg_buflen = msg_len;
    }

    if (input_len < msg_len ||  msg_len < 4) {
        log_info("Not enough values in buffer to generate request");
        assert(false);
    }

    switch (client->init_status) {
        case STARTUP_CLIENT:
            client->init_status = R;
            bufferevent_wrote(client->bev, server_auth_msg_1.msg, server_auth_msg_1.len);
            break;
        case R:
            struct message_list_node *curr_node = server_parameter_list.head;
            while(curr_node != NULL) {
                bufferevent_wrote(client->bev, curr_node->msg.msg, curr_node->msg.len);
                curr_node = curr_node->next;
            }

            // Hopefully client does not spam before getting ack
            client->init_status = COMPLETE_CLIENT;
            break;
        default:
            log_info("initialize client (first) called on initialized client");
            exit(-1);
            break;
    }
    evbuffer_drain(input, msg_buflen);
}


static void client_read_cb(struct bufferevent *bev, void *arg) {
    struct client_conn *client = arg;
    struct evbuffer *input = bufferevent_get_input(bev);
    size_t len = evbuffer_get_length(input);
    
    if (len < 5) {
        log_debug("Expected longer message");
        return;
    }
    unsigned char *data = evbuffer_pullup(input, 5);
    char msg_type = data[0];
    if (msg_type == 0) {
        alloc_startup_server(&client, input);
    }
    struct server_conn *srv = client->assigned_server;


    // screw it, pray that we got enough bytes if init message
    while (len >= 5) {
        // Verify full buffer arrival
        data = evbuffer_pullup(input, 5);

        int32_t msg_len = ntohl(*(int32_t*)(data+1));
        int32_t msg_buflen = msg_len + 1;
        if (msg_type == 0) {
            msg_len = ntohl(*(int32_t*)(data));
            msg_buflen = msg_len;
        }

        if ((int32_t)len < msg_buflen) {
            break; // Not complete
        }

        // Print message
        unsigned char *full_msg = evbuffer_pullup(input, msg_buflen);
        log_debug("Client msg received: type=%c length=%d", msg_type, msg_len);
        log_debug("Client message content: %s", full_msg);

        if (msg_type == 'Q') {
            // 'Q' message: query is text starting at full_msg+5, terminated by '\0'
            const char *query = (const char*)(full_msg+5);
            size_t qlen = msg_len+1 - 5; // total - header size
            // Print the query text
            log_text_data("Client Q query", query, qlen);
        } else if (msg_type == 'p') {
            // 'p' PasswordMessage: also textual (null-terminated)
            const char *password = (const char*)(full_msg+5);
            size_t plen = msg_len+1 - 5;
            log_text_data("Client p password", password, plen);
        } else {
            // For other message types, print hex data
            log_hex_data(full_msg, msg_len+1);
            // log_text_data("Mystery message dump", full_msg, msg_len+1);
        }

        if (client->init_status != COMPLETE_CLIENT) {
            log_info("Initializing client");
            switch (global_startup_status) {

                case UNINITIALIZED_STARTUP_GLOBAL:
                    log_info("Client global init");
                    startup_client_id = client->id;
                    first_initialize_client_conn(srv, client);
                    break;

                case IN_PROGRESS_STARTUP_GLOBAL:
                    if (startup_client_id != client->id) {
                        log_info("Client waiting for global init");
                        struct q_list_node *node = malloc(sizeof(struct q_list_node));
                        struct waiting_client *cli = malloc(sizeof(struct waiting_client));
                        cli->bev = bev;
                        cli->arg = arg;
                        node_init(node, (void *)cli);
                        enqueue(&waiting_client_queue, node);
                        return;
                    }
                    log_info("Client global init (in the thick of it)");
                    first_initialize_client_conn(srv, client);
                    break;
                
                case COMPLETE_STARTUP_GLOBAL:
                    initialize_client_conn(srv, client);
                    break;
            }
            len = evbuffer_get_length(input);
            continue;
        }

        // handle actual queries
        if (msg_type == 'Q') {
            // Handle queries as before
            handle_client_query(client, input);
        } else if (msg_type == 'p') {
            // PasswordMessage
            if (!client->assigned_server) {
                send_error_response(client, "No backend assigned yet");
                evbuffer_drain(input, msg_len+1);
                return;
            }

            struct server_conn *srv = client->assigned_server;
            // Forward password message to backend
            bufferevent_wrote(srv->bev, full_msg, msg_len+1);

            evbuffer_drain(input, msg_len+1);
            // Now we wait for backend to respond with AuthenticationOk or error.
        } else if (msg_type == 'X') {
            // Client wants to terminate the connection
            log_debug("Client sent Terminate (X), closing connection");
            if (client->assigned_server) {
                release_server(client->assigned_server);
                client->assigned_server = NULL;
            }
            bufferevent_free(client->bev);
            free(client);
            return;
        } else {
            // Other message types (X=Terminate, S=Sync, etc.) can be handled as needed.
            // If unsupported:
            evbuffer_drain(input, msg_len+1);
            send_error_response(client, "Unsupported message type from client");
            return;
        }

        evbuffer_drain(input, msg_buflen);
        len = evbuffer_get_length(input);
    }
}


// The first global initilization, must set global values and give them back to
//  the client
// @pre there is a valid message in the queue
static void first_initialize_server_conn(struct server_conn *srv, struct client_conn *client) {
    struct evbuffer *input = bufferevent_get_input(srv->bev);
    size_t input_len = evbuffer_get_length(input);

    unsigned char *data = evbuffer_pullup(input, 5);
    int32_t msg_len = ntohl(*(int32_t*)(data+1));
    int32_t msg_buflen = msg_len + 1;

    if (input_len < msg_len ||  msg_len < 4) {
        log_info("Not enough values in buffer to generate request");
        assert(false);
    }

    unsigned char *msgcpy = malloc(msg_buflen);
    memcpy(msgcpy, data, msg_buflen);
    // Could do assertions, idrc
    char msg_type = msgcpy[0];

    switch (srv->init_status) {
        case STARTUP_SERVER:
            server_auth_msg_1.msg = msgcpy;
            server_auth_msg_1.len = msg_buflen;
            // Early set, but hopefully ok
            srv->init_status = P;
            break;
        case P:
            struct message_list_node *node = malloc(sizeof(struct message_list_node));
            message_list_node_init(node, msgcpy, msg_len);
            message_list_insert(&server_parameter_list, node);
            // Is len guaranteed to be 5?
            if (msg_type == 'Z' && msg_len == 5) {
                srv->init_status = COMPLETE_SERVER;
                log_info("Server completed global alloc sequence");

                global_startup_status = COMPLETE_STARTUP_GLOBAL;
            }
            break;
        default:
            log_info("initialize server (first) called on initialized server");
            exit(-1);
            break;
    }
    bufferevent_wrote(client->bev, msgcpy, msg_buflen);
    evbuffer_drain(input, msg_buflen);
}

// Subsequent initilizations, must set global values and give them back to
//  the client
// @pre there is a valid message in the queue
static void initialize_server_conn(struct server_conn *srv, struct client_conn *client) {
    struct evbuffer *input = bufferevent_get_input(srv->bev);
    size_t input_len = evbuffer_get_length(input);

    unsigned char *data = evbuffer_pullup(input, 5);
    char msg_type = data[0];

    int32_t msg_len = ntohl(*(int32_t*)(data+1));
    int32_t msg_buflen = msg_len + 1;

    if (input_len < msg_len ||  msg_len < 4) {
        log_info("Not enough values in buffer to generate request");
        assert(false);
    }

    if (srv->init_status == COMPLETE_SERVER) {
        log_info("initialize server called on initialized server");
        assert(false);
    }
    
    if (msg_type == 'Z' && msg_len == 5) {
        srv->init_status = COMPLETE_SERVER;
        log_info("Server completed single alloc sequence");
    }

    bufferevent_wrote(client->bev, data, msg_buflen);
    evbuffer_drain(input, msg_buflen);
}



static void handle_server_read(struct server_conn *srv, struct client_conn *client) {
    struct evbuffer *input = bufferevent_get_input(srv->bev);
    size_t len = evbuffer_get_length(input);

    while (len >= 5) {
        // Verify full buffer arrival
        unsigned char *data = evbuffer_pullup(input, 5);
        char msg_type = data[0];
        int32_t msg_len = ntohl(*(int32_t*)(data+1));
        if ((int32_t)len < msg_len+1) {
            break; // Not complete
        }

        // Log message content
        unsigned char *full_msg = evbuffer_pullup(input, msg_len+1);
        log_debug("Server msg received: type=%c length=%d", msg_type, msg_len);

        log_debug("Server message content: %s", full_msg);

        if (msg_type == 'C' || msg_type == 'E' || msg_type == 'N') {
            // These are textual messages that end with '\0'
            const char *text = (const char*)(full_msg+5);
            size_t tlen = msg_len+1 - 5;
            char label[64];
            snprintf(label, sizeof(label), "Server msg type=%c", msg_type);
            log_text_data(label, text, tlen);
        } else if (msg_type == 'Q' || msg_type == 'p' || msg_type == 'Z' || msg_type == 'R' || msg_type == 'S' || msg_type == 'K' || msg_type == 'D' || msg_type == 'T') {
            // These have known structures, but for debugging let's just hex dump them
            char label[64];
            snprintf(label, sizeof(label), "Server msg type=%c", msg_type);
            log_hex_data((const unsigned char*)full_msg, msg_len+1);
        } else {
            // Unknown message type, just hex dump
            log_hex_data((const unsigned char*)full_msg, msg_len+1);
        }

        // Initialize if necessary
        if (srv->init_status != COMPLETE_SERVER) {
            switch (global_startup_status) {
                case UNINITIALIZED_STARTUP_GLOBAL:
                    log_info("ERROR: Client should initialize startup (given current protocol)");
                    exit(-1);
                    break;
                case IN_PROGRESS_STARTUP_GLOBAL:
                    // TODO fill in first! only this should be enough for 1 server conn
                    first_initialize_server_conn(srv, client);
                    break;
                case COMPLETE_STARTUP_GLOBAL:
                    initialize_server_conn(srv, client);
                    break;
            }
            len = evbuffer_get_length(input);
            continue;
        }

        // Handshake done, normal query handling
        if (msg_type == 'Z' && msg_len == 5) {
            char tstatus = full_msg[5];
            bufferevent_wrote(client->bev, full_msg, msg_len+1);
            if (tstatus == 'I') {
                release_server(client->assigned_server);
                client->assigned_server = NULL;
                // in_transaction? TODO
            }
        } else {
            // Just forward other messages
            bufferevent_wrote(client->bev, full_msg, msg_len+1);
        }

        evbuffer_drain(input, msg_len+1);
        len = evbuffer_get_length(input);
    }
}

/* In event callbacks, log errors */
static void client_event_cb(struct bufferevent *bev, short events, void *arg) {
    
    struct client_conn *client = arg;
    
    if (events & BEV_EVENT_ERROR) {
        int err = EVUTIL_SOCKET_ERROR();
        log_debug("Client connection error: %s", evutil_socket_error_to_string(err));
    }

    if (events & (BEV_EVENT_EOF | BEV_EVENT_ERROR)) {
        log_info("Client disconnected");
        if (client->assigned_server) {
            release_server(client->assigned_server);
            client->assigned_server = NULL;
        }
        bufferevent_free(bev);
        free(client);
    }
}

// // Thoughtful, arguably smarter, and arguably righter, assuming you got all
// //  the bits pefectly right. I am too lazy to verify it though.

// static void send_startup_message(struct server_conn *srv) {
//     // Minimal StartupMessage:
//     // int32_t length, int32_t protocol(196608), "user\0postgres\0database\0postgres\0\0"
//     const char *user = "admin";
//     const char *db = "benchbase";
//     size_t ulen = strlen(user);
//     size_t dlen = strlen(db);

//     int32_t length = 8 + (5 + 1) + (int32_t)ulen + 1 + (9 + 1) + (int32_t)dlen + 1 + 1;
//     char *startup = malloc(length);
//     int32_t net_length = htonl(length);
//     memcpy(startup, &net_length, 4);
//     int32_t protocol = htonl(196608);
//     memcpy(startup+4, &protocol, 4);

//     char *pos = startup+8;
//     strcpy(pos, "user");
//     pos += 5;
//     strcpy(pos, user);
//     pos += ulen+1;
//     strcpy(pos, "database");
//     pos += 9;
//     strcpy(pos, db);
//     pos += dlen+1;
//     *pos = '\0'; // final terminator

//     log_debug("Sending StartupMessage to backend: user=%s db=%s", user, db);
//     bufferevent_wrote(srv->bev, startup, length);
//     free(startup);
// }

static void server_event_cb(struct bufferevent *bev, short events, void *arg) {
    struct server_conn *srv = arg;

    if (events & BEV_EVENT_CONNECTED) {
        log_info("Backend connected");
        log_info("WARNING: this case is now unhandled! Let's see if we run into any issues!");
        log_info("I don't think we should, because the server should never proactively connect to us.");
        // SIDE NOTE: This seems to be never called? I will ignore it for now

        // // If we have a client currently assigned and that client has a startup packet,
        // // forward it to the backend now.
        // // Note: If we are using a pool of servers, we might connect them in advance.
        // // In that case, we won't have a client assigned yet. We'll handle that scenario
        // // when we actually assign the server to a client and have the startup packet.

        // // For this PoC, let's assume we connect on-demand or the server is assigned before sending queries.
        // // If not assigned yet, no startup packet to send.
        // if (srv->current_client && srv->current_client->startup_packet) {
        //     log_debug("Forwarding client's startup packet to backend");
        //     bufferevent_wrote(srv->bev, srv->current_client->startup_packet, srv->current_client->startup_packet_len);
        //     // After this, we wait for AuthenticationOk, ParameterStatus, BackendKeyData, ReadyForQuery from backend
        // } else {
        //     log_debug("No client startup packet to forward yet");
        // }
        return;
    }

    if (events & BEV_EVENT_ERROR) {
        int err = EVUTIL_SOCKET_ERROR();
        log_debug("Server connection error: %s", evutil_socket_error_to_string(err));
        log_debug("WARNING: This case is not thoughtfully handled!");
        log_debug("If we can't just treat this like fail-stop, think harder!!");
        log_debug("UPDATE: Actually, it might be ok, servers can reopen connections if they close");
        srv->in_use = 0;
        srv->current_client = NULL;
        srv->init_status = STARTUP_SERVER;
        bufferevent_free(srv->bev);
    }

    if (events & (BEV_EVENT_EOF | BEV_EVENT_ERROR)) {
        log_debug("Backend server disconnected");
        log_debug("WARNING: This case is no longer thoughtfully handled!");
        log_debug("If we can't just treat this like fail-stop, think harder!!");
        log_debug("UPDATE: Actually, it might be ok, servers can reopen connections if they close");


        if (srv->current_client) {
            send_error_response(srv->current_client, "Backend server disconnected");
            srv->current_client->init_status = STARTUP_CLIENT;
            srv->current_client->assigned_server = NULL;
        }
        bufferevent_free(srv->bev);
        srv->bev = NULL;
        srv->in_use = true;
        srv->current_client = NULL;
        srv->init_status = STARTUP_SERVER;
    }
}


/** Callbacks **/
/* In server_read_cb, log server messages */
static void server_read_cb(struct bufferevent *bev, void *arg) {
    struct server_conn *srv = arg;
    struct client_conn *client = srv->current_client;
    if (!client) {
        size_t len = evbuffer_get_length(bufferevent_get_input(bev));
        log_debug("Server sent %zu bytes but no client is assigned. Discarding.", len);
        evbuffer_drain(bufferevent_get_input(bev), len);
        return;
    }

    struct evbuffer *input = bufferevent_get_input(bev);
    size_t total_len = evbuffer_get_length(input);

    while (total_len >= 5) {
        unsigned char *hdr = evbuffer_pullup(input, 5);
        char msg_type = hdr[0];
        int32_t msg_len = ntohl(*(int32_t*)(hdr+1));
        if ((int32_t)total_len < msg_len+1) {
            break;
        }

        log_debug("Server msg: type=%c length=%d", msg_type, msg_len);
        // Then handle_server_read as before
        handle_server_read(srv, client);
        total_len = evbuffer_get_length(input);
    }
}

static void accept_cb(struct evconnlistener *listener, evutil_socket_t fd, struct sockaddr *addr, int socklen, void *ctx) {
    // lol
    struct client_conn *client = calloc(1, sizeof(*client));
    client->init_status = STARTUP_CLIENT;

    struct bufferevent *bev = bufferevent_socket_new(base, fd, BEV_OPT_CLOSE_ON_FREE);
    client->bev = bev;
    client->id = client_id_counter + 1;
    client_id_counter++;
    bufferevent_setcb(bev, client_read_cb, NULL, client_event_cb, client);
    bufferevent_enable(bev, EV_READ|EV_WRITE);
    log_info("Client connected");
}

static void init_backends(void) {
    for (int i=0; i<BACKEND_COUNT; i++) {
        struct server_conn *srv = &servers[i];
        srv->bev = NULL;
        srv->in_use = false;
        srv->index = i;
        srv->current_client = NULL;

        srv->init_status = STARTUP_SERVER;  // Initially no handshake done

        int sfd = socket(AF_INET, SOCK_STREAM, 0);
        if (sfd < 0) {
            log_debug("Failed to create backend socket");
            exit(1);
        }
        evutil_make_socket_nonblocking(sfd);

        struct sockaddr_in sin;
        memset(&sin, 0, sizeof(sin));
        sin.sin_family = AF_INET;
        sin.sin_port = htons(BACKEND_PORTS[i]);
        sin.sin_addr.s_addr = inet_addr(BACKENDS[i]);

        if (connect(sfd, (struct sockaddr*)&sin, sizeof(sin)) < 0 && errno != EINPROGRESS) {
            log_debug("Failed to connect to backend");
            close(sfd);
            exit(1);
        }

        srv->bev = bufferevent_socket_new(base, sfd, BEV_OPT_CLOSE_ON_FREE);
        bufferevent_setcb(srv->bev, server_read_cb, NULL, server_event_cb, srv);
        bufferevent_enable(srv->bev, EV_READ|EV_WRITE);
        log_info("Connected to a backend server (awaiting event callback for handshake)");
    }
}

int main(int argc, char **argv) {
    base = event_base_new();
    if (!base) {
        log_debug("Failed to create event_base");
        return 1;
    }

    struct sockaddr_in sin;
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = htons(LISTEN_PORT);
    sin.sin_addr.s_addr = inet_addr(LISTEN_ADDR);

    struct evconnlistener *listener = evconnlistener_new_bind(base, accept_cb, NULL,
        LEV_OPT_CLOSE_ON_FREE|LEV_OPT_REUSEABLE, -1, (struct sockaddr*)&sin, sizeof(sin));

    if (!listener) {
        perror("evconnlistener_new_bind");
        return 1;
    }

    init_backends();

    log_info("Proxy starting...");
    event_base_dispatch(base);

    evconnlistener_free(listener);
    event_base_free(base);
    return 0;
}
