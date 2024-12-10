#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <errno.h>
#include <event2/event.h>
#include <event2/listener.h>
#include <event2/bufferevent.h>
#include <event2/buffer.h>
#include <arpa/inet.h>

static const char *LISTEN_ADDR = "0.0.0.0";
static const int LISTEN_PORT = 5433;

static const char *BACKEND_ADDR = "127.0.0.1";
static const int BACKEND_PORT = 5432;

struct client_conn;
struct server_conn;

struct server_conn {
    struct bufferevent *bev;
    struct client_conn *current_client;
    int handshake_done; // Once we get ReadyForQuery after startup/auth
    int in_use;
};

struct client_conn {
    struct bufferevent *bev;
    struct server_conn *assigned_server;
    int in_transaction; // 1 if in a BEGIN...COMMIT/ROLLBACK transaction
    int awaiting_startup; // If we need to forward startup message
};

static struct event_base *base;

// For PoC, just one backend server in a pool
#define BACKEND_COUNT 1
static struct server_conn servers[BACKEND_COUNT];

static void log_info(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    fprintf(stdout, "[INFO] ");
    vfprintf(stdout, fmt, ap);
    fprintf(stdout, "\n");
    va_end(ap);
}
static void log_debug(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    fprintf(stdout, "[DEBUG] ");
    vfprintf(stdout, fmt, ap);
    fprintf(stdout, "\n");
    va_end(ap);
}

static void send_error_response(struct client_conn *client, const char *msg) {
    size_t msg_len = strlen(msg);
    size_t pkt_len = 1 + 4 + 1 + msg_len + 1 + 1; 
    char *err_buf = malloc(pkt_len);
    err_buf[0] = 'E';
    *(int32_t*)(err_buf+1) = htonl((int32_t)pkt_len);
    err_buf[5] = 'M';
    memcpy(err_buf+6, msg, msg_len);
    err_buf[6+msg_len] = '\0';
    err_buf[6+msg_len+1] = '\0';

    bufferevent_write(client->bev, err_buf, pkt_len);
    free(err_buf);
}

static struct server_conn* get_free_server(void) {
    for (int i = 0; i < BACKEND_COUNT; i++) {
        if (!servers[i].in_use) {
            return &servers[i];
        }
    }
    return NULL;
}

static void release_server(struct server_conn *srv) {
    if (srv) {
        srv->in_use = 0;
        srv->current_client = NULL;
    }
}

static int starts_with_keyword(const char *query, const char *keyword) {
    // skip leading whitespace
    while (*query && isspace((unsigned char)*query)) query++;
    size_t klen = strlen(keyword);
    return (strncasecmp(query, keyword, klen) == 0);
}

static void forward_message(struct bufferevent *from, struct bufferevent *to) {
    struct evbuffer *input = bufferevent_get_input(from);
    size_t len = evbuffer_get_length(input);
    if (len < 5) return; 

    unsigned char *hdr = evbuffer_pullup(input, 5);
    char msg_type = hdr[0];
    int32_t msg_len = ntohl(*(int32_t*)(hdr+1));
    if ((int32_t)len < msg_len+1) return; 

    unsigned char *full_msg = evbuffer_pullup(input, msg_len+1);
    // Write unchanged
    bufferevent_write(to, full_msg, msg_len+1);
    evbuffer_drain(input, msg_len+1);

    log_debug("Forwarded message type=%c length=%d", msg_type, msg_len);
}

static void handle_client_query(struct client_conn *client, unsigned char *full_msg, int32_t msg_len) {
    // full_msg points to the entire Q message: Q, len, query...
    // query starts at full_msg+5 and ends with '\0'
    const char *query = (const char*)(full_msg+5);

    int start_trans = 0;
    int end_trans = 0;

    if (starts_with_keyword(query, "BEGIN")) {
        start_trans = 1;
    } else if (starts_with_keyword(query, "COMMIT")) {
        end_trans = 1;
    } else if (starts_with_keyword(query, "ROLLBACK")) {
        end_trans = 1;
    }

    // If not in transaction and not starting one, it's autocommit mode.
    // Need a server per query
    struct server_conn *srv = client->assigned_server;

    if (!client->in_transaction && !start_trans) {
        // autocommit query
        if (!srv) {
            srv = get_free_server();
            if (!srv) {
                send_error_response(client, "No free backend connection");
                return;
            }
            srv->in_use = 1;
            srv->current_client = client;
            client->assigned_server = srv;
        }
    } else if (start_trans) {
        // Starting a transaction block
        if (!srv) {
            srv = get_free_server();
            if (!srv) {
                send_error_response(client, "No free backend connection");
                return;
            }
            srv->in_use = 1;
            srv->current_client = client;
            client->assigned_server = srv;
        }
        client->in_transaction = 1;
    }

    // Just forward the query now.
    bufferevent_write(client->assigned_server->bev, full_msg, msg_len+1);

    // On COMMIT/ROLLBACK, we wait for ReadyForQuery to finalize the transaction
    // On autocommit queries (no BEGIN), once we get ReadyForQuery, we release server
}

static void handle_client_read(struct client_conn *client) {
    struct evbuffer *input = bufferevent_get_input(client->bev);
    for (;;) {
        size_t available = evbuffer_get_length(input);
        if (available < 5) break;
        unsigned char *hdr = evbuffer_pullup(input, 5);
        char msg_type = hdr[0];
        int32_t msg_len = ntohl(*(int32_t*)(hdr+1));
        if ((int32_t)available < msg_len+1) break;

        unsigned char *full_msg = evbuffer_pullup(input, msg_len+1);

        log_debug("Client msg received: type=%c length=%d", msg_type, msg_len);

        // Drain after handling
        evbuffer_drain(input, msg_len+1);

        if (msg_type == 'Q') {
            handle_client_query(client, full_msg, msg_len);
        } else if (msg_type == 'p') {
            // PasswordMessage, forward as is
            if (!client->assigned_server) {
                // Need a server
                struct server_conn *srv = get_free_server();
                if (!srv) {
                    send_error_response(client, "No free backend for auth");
                    return;
                }
                srv->in_use = 1;
                srv->current_client = client;
                client->assigned_server = srv;
            }
            bufferevent_write(client->assigned_server->bev, full_msg, msg_len+1);
        } else if (msg_type == 'X') {
            log_debug("Client sent Terminate (X), closing connection");
            // Terminate
            if (client->assigned_server) {
                release_server(client->assigned_server);
                client->assigned_server = NULL;
            }
            bufferevent_free(client->bev);
            free(client);
            return; // no more processing
        } else {
            // Startup or SSLRequest or other messages
            // For simplicity, just forward to server if assigned
            // If startup message and no server assigned, assign server and forward
            if (!client->assigned_server) {
                struct server_conn *srv = get_free_server();
                if (!srv) {
                    send_error_response(client, "No free backend");
                    return;
                }
                srv->in_use = 1;
                srv->current_client = client;
                client->assigned_server = srv;
            }
            bufferevent_write(client->assigned_server->bev, full_msg, msg_len+1);
        }
    }
}

static void handle_server_read(struct server_conn *srv) {
    struct evbuffer *input = bufferevent_get_input(srv->bev);
    struct client_conn *client = srv->current_client;
    if (!client) {
        // no client, drain data
        evbuffer_drain(input, evbuffer_get_length(input));
        return;
    }

    for (;;) {
        size_t available = evbuffer_get_length(input);
        if (available < 5) break;
        unsigned char *hdr = evbuffer_pullup(input, 5);
        char msg_type = hdr[0];
        int32_t msg_len = ntohl(*(int32_t*)(hdr+1));
        if ((int32_t)available < msg_len+1) break;

        unsigned char *full_msg = evbuffer_pullup(input, msg_len+1);
        // Forward to client unchanged
        bufferevent_write(client->bev, full_msg, msg_len+1);
        evbuffer_drain(input, msg_len+1);

        log_debug("Server msg: type=%c length=%d", msg_type, msg_len);

        if (msg_type == 'Z' && msg_len == 5) {
            // ReadyForQuery
            // Check if transaction ended
            // The status byte is full_msg[5], after type and length
            char status = full_msg[5];
            if (client->in_transaction && status == 'I') {
                // End of explicit transaction
                client->in_transaction = 0;
                // keep server assigned if you like, or release?
                // transaction pooling means we can release it if done
                release_server(client->assigned_server);
                client->assigned_server = NULL;
            } else if (!client->in_transaction && status == 'I') {
                // Autocommit query ended, release server
                if (client->assigned_server) {
                    release_server(client->assigned_server);
                    client->assigned_server = NULL;
                }
            }
        }
    }
}

// Callbacks
static void client_read_cb(struct bufferevent *bev, void *arg) {
    struct client_conn *client = arg;
    handle_client_read(client);
}

static void client_event_cb(struct bufferevent *bev, short events, void *arg) {
    struct client_conn *client = arg;
    if (events & (BEV_EVENT_EOF | BEV_EVENT_ERROR)) {
        log_info("Client disconnected");
        if (client->assigned_server) {
            release_server(client->assigned_server);
        }
        bufferevent_free(bev);
        free(client);
    }
}

static void server_read_cb(struct bufferevent *bev, void *arg) {
    struct server_conn *srv = arg;
    handle_server_read(srv);
}

static void server_event_cb(struct bufferevent *bev, short events, void *arg) {
    struct server_conn *srv = arg;
    if (events & (BEV_EVENT_EOF | BEV_EVENT_ERROR)) {
        log_info("Backend server disconnected");
        if (srv->current_client) {
            send_error_response(srv->current_client, "Backend server disconnected");
            srv->current_client->in_transaction = 0;
            srv->current_client->assigned_server = NULL;
        }
        bufferevent_free(srv->bev);
        srv->bev = NULL;
        srv->in_use = 0;
        srv->current_client = NULL;
    }
}

static void accept_cb(struct evconnlistener *listener, evutil_socket_t fd, struct sockaddr *addr, int socklen, void *ctx) {
    struct client_conn *client = calloc(1, sizeof(*client));
    client->awaiting_startup = 1; // We'll forward startup to backend
    struct bufferevent *bev = bufferevent_socket_new(base, fd, BEV_OPT_CLOSE_ON_FREE);
    client->bev = bev;
    bufferevent_setcb(bev, client_read_cb, NULL, client_event_cb, client);
    bufferevent_enable(bev, EV_READ|EV_WRITE);
    log_info("Client connected");
}

static void init_backends(void) {
    for (int i=0; i<BACKEND_COUNT; i++) {
        struct server_conn *srv = &servers[i];
        srv->in_use = 0;
        srv->handshake_done = 0;
        srv->current_client = NULL;

        int sfd = socket(AF_INET, SOCK_STREAM, 0);
        evutil_make_socket_nonblocking(sfd);
        struct sockaddr_in sin;
        memset(&sin, 0, sizeof(sin));
        sin.sin_family = AF_INET;
        sin.sin_port = htons(BACKEND_PORT);
        sin.sin_addr.s_addr = inet_addr(BACKEND_ADDR);
        connect(sfd, (struct sockaddr*)&sin, sizeof(sin));

        srv->bev = bufferevent_socket_new(base, sfd, BEV_OPT_CLOSE_ON_FREE);
        bufferevent_setcb(srv->bev, server_read_cb, NULL, server_event_cb, srv);
        bufferevent_enable(srv->bev, EV_READ|EV_WRITE);
        log_info("Connected to a backend server (awaiting event callback for handshake)");
    }
}

int main(int argc, char **argv) {
    base = event_base_new();
    if (!base) {
        fprintf(stderr, "Failed to create event_base\n");
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

