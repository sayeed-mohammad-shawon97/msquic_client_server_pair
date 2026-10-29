/*++


Abstract:

    Standalone msquic "GET a file" SERVER (derived from the msquic quicsample).

    Everything is hard coded in the CONFIGURATION section below; there are no
    command line arguments. The server listens on UDP port 4567 using ALPN
    "sample". For each connection it accepts one bidirectional stream, reads a
    request line of the form "GET /<filename>\r\n", looks the file up in
    SERVER_ROOT and sends its bytes back on the same stream followed by a FIN.

--*/

#define _CRT_SECURE_NO_WARNINGS 1

#ifdef _WIN32

#pragma warning(disable:5105)
#endif
#include "msquic.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef UNREFERENCED_PARAMETER
#define UNREFERENCED_PARAMETER(P) (void)(P)
#endif

// ===========================================================================
// CONFIGURATION (edit these)
// ===========================================================================

#define SERVER_CERT_FILE   "cert.pem"   // Server certificate (PEM).
#define SERVER_KEY_FILE    "key.pem"    // Server private key (PEM, no password).
#define SERVER_ROOT        "./www"      // Directory files are served from.

const uint16_t UdpPort = 4567;          // UDP port to listen on.
const uint64_t IdleTimeoutMs = 1000;    // Idle timeout (1 second).

const uint32_t MaxFileSize = 64 * 1024 * 1024; // Largest file served.

// ===========================================================================

#define MAX_FILENAME_LEN 256
#define MAX_REQUEST_LEN  512

//
// Application error codes the server uses when aborting a stream.
//
#define APP_ERR_BAD_REQUEST 400
#define APP_ERR_FORBIDDEN   403
#define APP_ERR_NOT_FOUND   404
#define APP_ERR_TOO_LARGE   413

//
// The (optional) registration configuration for the app. This sets a name for
// the app (used for persistent storage and for debugging). It also configures
// the execution profile, using the default "low latency" profile.
//
const QUIC_REGISTRATION_CONFIG RegConfig = { "quicserver", QUIC_EXECUTION_PROFILE_LOW_LATENCY };

//
// The protocol name used in the Application Layer Protocol Negotiation (ALPN).
//
const QUIC_BUFFER Alpn = { sizeof("sample") - 1, (uint8_t*)"sample" };

//
// The QUIC API/function table returned from MsQuicOpen2. It contains all the
// functions called by the app to interact with MsQuic.
//
const QUIC_API_TABLE* MsQuic;

//
// The QUIC handle to the registration object. This is the top level API object
// that represents the execution context for all work done by MsQuic on behalf
// of the app.
//
HQUIC Registration;

//
// The QUIC handle to the configuration object. This object abstracts the
// connection configuration. This includes TLS configuration and any other
// QUIC layer settings.
//
HQUIC Configuration;

//
// Accepts only flat file names: letters, digits, '.', '_' and '-', not starting
// with '.'. This rules out path separators and "..", so a request can never
// leave SERVER_ROOT.
//
BOOLEAN
IsSafeFileName(
    _In_z_ const char* Name
    )
{
    size_t Len = strlen(Name);
    if (Len == 0 || Len >= MAX_FILENAME_LEN || Name[0] == '.') {
        return FALSE;
    }
    for (size_t i = 0; i < Len; i++) {
        char c = Name[i];
        if (!((c >= 'a' && c <= 'z') ||
              (c >= 'A' && c <= 'Z') ||
              (c >= '0' && c <= '9') ||
              c == '.' || c == '_' || c == '-')) {
            return FALSE;
        }
    }
    return TRUE;
}

//
// Pulls <name> out of a "GET /<name>" request line.
//
BOOLEAN
ParseGetRequest(
    _In_z_ const char* Request,
    _Out_writes_bytes_(NameLen) char* Name,
    _In_ size_t NameLen
    )
{
    if (strncmp(Request, "GET /", 5) != 0) {
        return FALSE;
    }
    const char* p = Request + 5;
    size_t n = 0;
    while (*p != '\0' && *p != ' ' && *p != '\r' && *p != '\n') {
        if (n + 1 >= NameLen) {
            return FALSE;
        }
        Name[n++] = *p++;
    }
    Name[n] = '\0';
    return n > 0;
}

//
// Per-stream state on the server: the request bytes received so far.
//
typedef struct SERVER_STREAM_CTX {
    char Request[MAX_REQUEST_LEN];
    uint32_t RequestLen;
    BOOLEAN Overflow;
} SERVER_STREAM_CTX;

//
// Aborts the server's send direction with an application error code. The
// client sees this as QUIC_STREAM_EVENT_PEER_SEND_ABORTED with that code.
//
void
ServerReject(
    _In_ HQUIC Stream,
    _In_ uint64_t ErrorCode
    )
{
    printf("[strm][%p] Rejecting request, code %llu\n", Stream, (unsigned long long)ErrorCode);
    MsQuic->StreamShutdown(Stream, QUIC_STREAM_SHUTDOWN_FLAG_ABORT_SEND, ErrorCode);
}

//
// Parses the request, loads the file from SERVER_ROOT and sends it.
//
void
ServerSend(
    _In_ HQUIC Stream,
    _In_ SERVER_STREAM_CTX* Ctx
    )
{
    char Name[MAX_FILENAME_LEN];
    char Path[MAX_FILENAME_LEN + 1024];

    if (Ctx->Overflow) {
        ServerReject(Stream, APP_ERR_BAD_REQUEST);
        return;
    }
    Ctx->Request[Ctx->RequestLen] = '\0';

    if (!ParseGetRequest(Ctx->Request, Name, sizeof(Name))) {
        ServerReject(Stream, APP_ERR_BAD_REQUEST);
        return;
    }
    if (!IsSafeFileName(Name)) {
        ServerReject(Stream, APP_ERR_FORBIDDEN);
        return;
    }

    snprintf(Path, sizeof(Path), "%s/%s", SERVER_ROOT, Name);
    FILE* File = fopen(Path, "rb");
    if (File == NULL) {
        printf("[strm][%p] GET /%s -> not found (%s)\n", Stream, Name, Path);
        ServerReject(Stream, APP_ERR_NOT_FOUND);
        return;
    }

    fseek(File, 0, SEEK_END);
    long FileSize = ftell(File);
    fseek(File, 0, SEEK_SET);
    if (FileSize < 0 || (unsigned long)FileSize > MaxFileSize) {
        fclose(File);
        ServerReject(Stream, APP_ERR_TOO_LARGE);
        return;
    }

    if (FileSize == 0) {
        //
        // Empty file: nothing to send, just a FIN.
        //
        fclose(File);
        printf("[strm][%p] GET /%s -> empty file\n", Stream, Name);
        MsQuic->StreamShutdown(Stream, QUIC_STREAM_SHUTDOWN_FLAG_GRACEFUL, 0);
        return;
    }

    //
    // Allocates and builds the buffer to send over the stream: the QUIC_BUFFER
    // descriptor followed by the file contents.
    //
    void* SendBufferRaw = malloc(sizeof(QUIC_BUFFER) + (size_t)FileSize);
    if (SendBufferRaw == NULL) {
        fclose(File);
        printf("SendBuffer allocation failed!\n");
        MsQuic->StreamShutdown(Stream, QUIC_STREAM_SHUTDOWN_FLAG_ABORT, 0);
        return;
    }
    QUIC_BUFFER* SendBuffer = (QUIC_BUFFER*)SendBufferRaw;
    SendBuffer->Buffer = (uint8_t*)SendBufferRaw + sizeof(QUIC_BUFFER);
    SendBuffer->Length = (uint32_t)FileSize;

    size_t Read = fread(SendBuffer->Buffer, 1, (size_t)FileSize, File);
    fclose(File);
    if (Read != (size_t)FileSize) {
        printf("[strm][%p] Short read on %s\n", Stream, Path);
        free(SendBufferRaw);
        MsQuic->StreamShutdown(Stream, QUIC_STREAM_SHUTDOWN_FLAG_ABORT, 0);
        return;
    }

    printf("[strm][%p] GET /%s -> sending %ld bytes...\n", Stream, Name, FileSize);

    //
    // Sends the buffer over the stream. Note the FIN flag is passed along with
    // the buffer. This indicates this is the last buffer on the stream and the
    // the stream is shut down (in the send direction) immediately after.
    //
    QUIC_STATUS Status;
    if (QUIC_FAILED(Status = MsQuic->StreamSend(Stream, SendBuffer, 1, QUIC_SEND_FLAG_FIN, SendBuffer))) {
        printf("StreamSend failed, 0x%x!\n", Status);
        free(SendBufferRaw);
        MsQuic->StreamShutdown(Stream, QUIC_STREAM_SHUTDOWN_FLAG_ABORT, 0);
    }
}

//
// The server's callback for stream events from MsQuic.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
_Function_class_(QUIC_STREAM_CALLBACK)
QUIC_STATUS
QUIC_API
ServerStreamCallback(
    _In_ HQUIC Stream,
    _In_opt_ void* Context,
    _Inout_ QUIC_STREAM_EVENT* Event
    )
{
    SERVER_STREAM_CTX* Ctx = (SERVER_STREAM_CTX*)Context;
    switch (Event->Type) {
    case QUIC_STREAM_EVENT_SEND_COMPLETE:
        //
        // A previous StreamSend call has completed, and the context is being
        // returned back to the app.
        //
        free(Event->SEND_COMPLETE.ClientContext);
        printf("[strm][%p] Data sent\n", Stream);
        break;
    case QUIC_STREAM_EVENT_RECEIVE:
        //
        // Data was received from the peer on the stream: collect the request.
        //
        printf("[strm][%p] Data received\n", Stream);
        if (Ctx != NULL) {
            for (uint32_t i = 0; i < Event->RECEIVE.BufferCount; i++) {
                const QUIC_BUFFER* B = &Event->RECEIVE.Buffers[i];
                uint32_t Space = (uint32_t)sizeof(Ctx->Request) - 1 - Ctx->RequestLen;
                if (B->Length > Space) {
                    Ctx->Overflow = TRUE;
                    break;
                }
                memcpy(Ctx->Request + Ctx->RequestLen, B->Buffer, B->Length);
                Ctx->RequestLen += B->Length;
            }
        }
        break;
    case QUIC_STREAM_EVENT_PEER_SEND_SHUTDOWN:
        //
        // The peer gracefully shut down its send direction of the stream, so
        // the whole request has arrived. Reply with the file.
        //
        printf("[strm][%p] Peer shut down\n", Stream);
        if (Ctx != NULL) {
            ServerSend(Stream, Ctx);
        } else {
            MsQuic->StreamShutdown(Stream, QUIC_STREAM_SHUTDOWN_FLAG_ABORT, 0);
        }
        break;
    case QUIC_STREAM_EVENT_PEER_SEND_ABORTED:
        //
        // The peer aborted its send direction of the stream.
        //
        printf("[strm][%p] Peer aborted\n", Stream);
        MsQuic->StreamShutdown(Stream, QUIC_STREAM_SHUTDOWN_FLAG_ABORT, 0);
        break;
    case QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE:
        //
        // Both directions of the stream have been shut down and MsQuic is done
        // with the stream. It can now be safely cleaned up.
        //
        printf("[strm][%p] All done\n", Stream);
        free(Ctx);
        MsQuic->StreamClose(Stream);
        break;
    default:
        break;
    }
    return QUIC_STATUS_SUCCESS;
}

//
// The server's callback for connection events from MsQuic.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
_Function_class_(QUIC_CONNECTION_CALLBACK)
QUIC_STATUS
QUIC_API
ServerConnectionCallback(
    _In_ HQUIC Connection,
    _In_opt_ void* Context,
    _Inout_ QUIC_CONNECTION_EVENT* Event
    )
{
    UNREFERENCED_PARAMETER(Context);
    switch (Event->Type) {
    case QUIC_CONNECTION_EVENT_CONNECTED:
        //
        // The handshake has completed for the connection.
        //
        printf("[conn][%p] Connected\n", Connection);
        MsQuic->ConnectionSendResumptionTicket(Connection, QUIC_SEND_RESUMPTION_FLAG_NONE, 0, NULL);
        break;
    case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_TRANSPORT:
        //
        // The connection has been shut down by the transport.
        //
        if (Event->SHUTDOWN_INITIATED_BY_TRANSPORT.Status == QUIC_STATUS_CONNECTION_IDLE) {
            printf("[conn][%p] Successfully shut down on idle.\n", Connection);
        } else {
            printf("[conn][%p] Shut down by transport, 0x%x\n", Connection, Event->SHUTDOWN_INITIATED_BY_TRANSPORT.Status);
        }
        break;
    case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_PEER:
        //
        // The connection was explicitly shut down by the peer.
        //
        printf("[conn][%p] Shut down by peer, 0x%llu\n", Connection, (unsigned long long)Event->SHUTDOWN_INITIATED_BY_PEER.ErrorCode);
        break;
    case QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE:
        //
        // The connection has completed the shutdown process and is ready to be
        // safely cleaned up.
        //
        printf("[conn][%p] All done\n", Connection);
        MsQuic->ConnectionClose(Connection);
        break;
    case QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED:
        {
            //
            // The peer has started/created a new stream. The app MUST set the
            // callback handler before returning. Each stream gets its own
            // context to collect the request, freed when the stream is done.
            //
            printf("[strm][%p] Peer started\n", Event->PEER_STREAM_STARTED.Stream);
            SERVER_STREAM_CTX* StreamCtx = (SERVER_STREAM_CTX*)calloc(1, sizeof(SERVER_STREAM_CTX));
            MsQuic->SetCallbackHandler(Event->PEER_STREAM_STARTED.Stream, (void*)ServerStreamCallback, StreamCtx);
            if (StreamCtx == NULL) {
                MsQuic->StreamShutdown(Event->PEER_STREAM_STARTED.Stream, QUIC_STREAM_SHUTDOWN_FLAG_ABORT, 0);
            }
        }
        break;
    case QUIC_CONNECTION_EVENT_RESUMED:
        //
        // The connection succeeded in doing a TLS resumption of a previous
        // connection's session.
        //
        printf("[conn][%p] Connection resumed!\n", Connection);
        break;
    default:
        break;
    }
    return QUIC_STATUS_SUCCESS;
}

//
// The server's callback for listener events from MsQuic.
//
_IRQL_requires_max_(PASSIVE_LEVEL)
_Function_class_(QUIC_LISTENER_CALLBACK)
QUIC_STATUS
QUIC_API
ServerListenerCallback(
    _In_ HQUIC Listener,
    _In_opt_ void* Context,
    _Inout_ QUIC_LISTENER_EVENT* Event
    )
{
    UNREFERENCED_PARAMETER(Listener);
    UNREFERENCED_PARAMETER(Context);
    QUIC_STATUS Status = QUIC_STATUS_NOT_SUPPORTED;
    switch (Event->Type) {
    case QUIC_LISTENER_EVENT_NEW_CONNECTION:
        //
        // A new connection is being attempted by a client. For the handshake to
        // proceed, the server must provide a configuration for QUIC to use. The
        // app MUST set the callback handler before returning.
        //
        MsQuic->SetCallbackHandler(Event->NEW_CONNECTION.Connection, (void*)ServerConnectionCallback, NULL);
        Status = MsQuic->ConnectionSetConfiguration(Event->NEW_CONNECTION.Connection, Configuration);
        break;
    default:
        break;
    }
    return Status;
}

//
// Helper function to load the server configuration, using the hard coded
// certificate and key files.
//
BOOLEAN
ServerLoadConfiguration()
{
    QUIC_SETTINGS Settings = {0};
    //
    // Configures the server's idle timeout.
    //
    Settings.IdleTimeoutMs = IdleTimeoutMs;
    Settings.IsSet.IdleTimeoutMs = TRUE;
    //
    // Configures the server's resumption level to allow for resumption and
    // 0-RTT.
    //
    Settings.ServerResumptionLevel = QUIC_SERVER_RESUME_AND_ZERORTT;
    Settings.IsSet.ServerResumptionLevel = TRUE;
    //
    // Configures the server's settings to allow for the peer to open a single
    // bidirectional stream. By default connections are not configured to allow
    // any streams from the peer.
    //
    Settings.PeerBidiStreamCount = 1;
    Settings.IsSet.PeerBidiStreamCount = TRUE;

    //
    // Load the server's certificate and private key from the PEM files.
    //
    QUIC_CERTIFICATE_FILE CertFile;
    memset(&CertFile, 0, sizeof(CertFile));
    CertFile.CertificateFile = (char*)SERVER_CERT_FILE;
    CertFile.PrivateKeyFile = (char*)SERVER_KEY_FILE;

    QUIC_CREDENTIAL_CONFIG CredConfig;
    memset(&CredConfig, 0, sizeof(CredConfig));
    CredConfig.Flags = QUIC_CREDENTIAL_FLAG_NONE;
    CredConfig.Type = QUIC_CREDENTIAL_TYPE_CERTIFICATE_FILE;
    CredConfig.CertificateFile = &CertFile;

    //
    // Allocate/initialize the configuration object, with the configured ALPN
    // and settings.
    //
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    if (QUIC_FAILED(Status = MsQuic->ConfigurationOpen(Registration, &Alpn, 1, &Settings, sizeof(Settings), NULL, &Configuration))) {
        printf("ConfigurationOpen failed, 0x%x!\n", Status);
        return FALSE;
    }

    //
    // Loads the TLS credential part of the configuration.
    //
    if (QUIC_FAILED(Status = MsQuic->ConfigurationLoadCredential(Configuration, &CredConfig))) {
        printf("ConfigurationLoadCredential failed, 0x%x! (are %s and %s present?)\n",
            Status, SERVER_CERT_FILE, SERVER_KEY_FILE);
        return FALSE;
    }

    return TRUE;
}

//
// Runs the server side of the protocol.
//
void
RunServer()
{
    QUIC_STATUS Status;
    HQUIC Listener = NULL;

    printf("Serving files from: %s\n", SERVER_ROOT);

    //
    // Configures the address used for the listener to listen on all IP
    // addresses and the given UDP port.
    //
    QUIC_ADDR Address = {0};
    QuicAddrSetFamily(&Address, QUIC_ADDRESS_FAMILY_UNSPEC);
    QuicAddrSetPort(&Address, UdpPort);

    //
    // Load the server configuration.
    //
    if (!ServerLoadConfiguration()) {
        return;
    }

    //
    // Create/allocate a new listener object.
    //
    if (QUIC_FAILED(Status = MsQuic->ListenerOpen(Registration, ServerListenerCallback, NULL, &Listener))) {
        printf("ListenerOpen failed, 0x%x!\n", Status);
        goto Error;
    }

    //
    // Starts listening for incoming connections.
    //
    if (QUIC_FAILED(Status = MsQuic->ListenerStart(Listener, &Alpn, 1, &Address))) {
        printf("ListenerStart failed, 0x%x!\n", Status);
        goto Error;
    }

    //
    // Continue listening for connections until the Enter key is pressed.
    //
    printf("Listening on UDP port %u. Press Enter to exit.\n\n", UdpPort);
    (void)getchar();

Error:

    if (Listener != NULL) {
        MsQuic->ListenerClose(Listener);
    }
}

int
QUIC_MAIN_EXPORT
main(void)
{
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;

    //
    // Open a handle to the library and get the API function table.
    //
    if (QUIC_FAILED(Status = MsQuicOpen2(&MsQuic))) {
        printf("MsQuicOpen2 failed, 0x%x!\n", Status);
        goto Error;
    }

    //
    // Create a registration for the app's connections.
    //
    if (QUIC_FAILED(Status = MsQuic->RegistrationOpen(&RegConfig, &Registration))) {
        printf("RegistrationOpen failed, 0x%x!\n", Status);
        goto Error;
    }

    RunServer();

Error:

    if (MsQuic != NULL) {
        if (Configuration != NULL) {
            MsQuic->ConfigurationClose(Configuration);
        }
        if (Registration != NULL) {
            //
            // This will block until all outstanding child objects have been
            // closed.
            //
            MsQuic->RegistrationClose(Registration);
        }
        MsQuicClose(MsQuic);
    }

    return (int)Status;
}
